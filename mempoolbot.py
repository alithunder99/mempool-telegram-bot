#!/usr/bin/env python3
"""
Mempool Monitor -> Telegram  (v12, Muun)

Detecta (por plantilla de witness, no solo por fee):
  - Retiro on-chain de la app
  - Pago Lightning saliente (output P2WSH del swap)
  - Recovery Tool
Filtro de monto duro: MIN_SATS < monto < MAX_SATS.
Agrupa direcciones por cuenta (SQLite) y arma la linea de tiempo.

Variables de entorno:
  TELEGRAM_TOKEN, TELEGRAM_CHAT_ID  (obligatorias)
  MIN_SATS=600  MAX_SATS=30000  FEE_SPLIT=20000
  MIN_CONF=baja|media|alta   (confianza minima para notificar)
  DB_PATH=muun.db  TIMELINE_N=12  MAX_ADDR_SCAN=8
"""

import os
import re
import json
import time
import queue
import sqlite3
import threading
from collections import deque, Counter

import requests
from websocket import WebSocketApp

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
WS_URL = "wss://mempool.space/api/v1/ws"
API_BASE = "https://mempool.space/api"

MIN_SATS = int(os.getenv("MIN_SATS", "600"))
MAX_SATS = int(os.getenv("MAX_SATS", "30000"))
FEE_SPLIT = int(os.getenv("FEE_SPLIT", "20000"))
ALLOWED_FEES = (151, 303)
LEVELS = {"baja": 1, "media": 2, "alta": 3}
MIN_LEVEL = LEVELS.get(os.getenv("MIN_CONF", "baja").lower(), 1)
DB_PATH = os.getenv("DB_PATH", "muun.db")
TIMELINE_N = int(os.getenv("TIMELINE_N", "12"))
MAX_ADDR_SCAN = int(os.getenv("MAX_ADDR_SCAN", "8"))

if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
    print("Faltan TELEGRAM_TOKEN o TELEGRAM_CHAT_ID")
    raise SystemExit(1)

SEEN = deque(maxlen=5000)
SEEN_SET = set()
NOTIFY_Q = queue.Queue()
STATS = Counter()

NAME_LEVEL = {1: "baja", 2: "media", 3: "alta"}
ICON_LEVEL = {1: "🟡", 2: "🟠", 3: "🟢"}
KIND_LABEL = {
    "ret": "🏦 Retiro on-chain",
    "ln": "⚡ Pago Lightning (swap)",
    "rec": "🛠 Recovery Tool",
    "dep_ln": "⚡ Depósito Lightning (HTLC)",
    "dep_onchain": "⬇️ Depósito on-chain",
    "gasto": "⬆️ Salida de fondos",
}
LIVE_KINDS = ("ret", "ln", "rec")

# ------------------------------------------------------------------
# Plantillas de script (las claves/hashes/locktime cambian, la forma no)
# ------------------------------------------------------------------
MULTISIG = re.compile(rb"^\x52\x21[\x02\x03].{32}\x21[\x02\x03].{32}\x52\xae$", re.S)
SWAP = re.compile(
    rb"^\x21[\x02\x03].{32}\xac\x64\x76\xa9\x14.{20}\x88\xad\x03.{3}\xb1\x67"
    rb"\x21[\x02\x03].{32}\xad\x82\x01\x20\x88\xa9\x14.{20}\x87\x68$",
    re.S,
)


def input_kind(v: dict):
    t = (v.get("prevout") or {}).get("scriptpubkey_type")
    w = v.get("witness") or []
    try:
        if t == "v0_p2wsh" and len(w) == 4:
            s = bytes.fromhex(w[-1])
            if SWAP.match(s) and len(bytes.fromhex(w[0])) == 32:
                return "swap"
            if MULTISIG.match(s) and w[0] == "":
                return "msig"
        if t == "v1_p2tr" and len(w) == 1:
            b = bytes.fromhex(w[0])
            if len(b) == 65 and b[-1] == 0x01:  # Schnorr + SIGHASH_ALL explicito
                return "tr65"
    except ValueError:
        pass
    return None


def in_range(x: int) -> bool:
    return MIN_SATS < x < MAX_SATS


def fee_matches_amount(fee: int, amount: int) -> bool:
    if fee == 151:
        return amount < FEE_SPLIT
    if fee == 303:
        return amount >= FEE_SPLIT
    return False


def prefilter(tx: dict) -> bool:
    """Filtro barato (hilo del websocket). Sin llamadas de red."""
    vin, vout = tx.get("vin") or [], tx.get("vout") or []
    if not vin or not (1 <= len(vout) <= 2):
        return False
    if tx.get("version") not in (1, 2) or tx.get("locktime") != 0:
        return False
    for v in vin:
        if v.get("sequence") != 0xFFFFFFFF:
            return False
        if (v.get("prevout") or {}).get("scriptpubkey_type") not in ("v0_p2wsh", "v1_p2tr"):
            return False
    return any(in_range(o.get("value", 0)) for o in vout)


def classify(tx: dict):
    """Devuelve dict(kind, tipo, score 1-3, amount, change_addr) o None."""
    vin, vout = tx.get("vin", []), tx.get("vout", [])
    kinds = [input_kind(v) for v in vin]
    if not kinds or None in kinds:
        return None
    fee, size, ver = tx.get("fee", 0), tx.get("size", 0), tx.get("version")
    has_swap, has_tr = "swap" in kinds, "tr65" in kinds
    all_msig = all(k == "msig" for k in kinds)

    # --- Recovery Tool: v2, 1 output, fee ~ 1 sat/byte
    if ver == 2:
        if len(vout) != 1:
            return None
        amount = vout[0].get("value", 0)
        if not (fee in ALLOWED_FEES or abs(fee - size) <= 2):
            return None
        score = 2 if all_msig else 1
        if fee_matches_amount(fee, amount):
            score += 1
        if not in_range(amount):
            return None
        return dict(kind="rec", score=min(score, 3), amount=amount, change=None)

    # --- App (v1)
    if has_swap and has_tr:
        score = 3
    elif has_swap:
        score = 2
    else:
        score = 1

    wsh = [o for o in vout if o.get("scriptpubkey_type") == "v0_p2wsh"]
    if wsh:  # pago Lightning: fondeo del HTLC del swap
        if len(wsh) != 1:
            return None
        amount = wsh[0].get("value", 0)
        others = [o for o in vout if o is not wsh[0]]
        change = others[0] if others and others[0].get("scriptpubkey_type") == "v1_p2tr" else None
        if not in_range(amount):
            return None
        return dict(kind="ln", score=score, amount=amount,
                    change=(change or {}).get("scriptpubkey_address"))

    # retiro on-chain: el cambio de Muun V5 vuelve como P2TR
    tr_outs = [o for o in vout if o.get("scriptpubkey_type") == "v1_p2tr"]
    change, dests = None, vout
    if len(vout) == 2 and len(tr_outs) == 1:
        change = tr_outs[0]
        dests = [o for o in vout if o is not change]
    cands = [o.get("value", 0) for o in dests if in_range(o.get("value", 0))]
    if not cands:
        return None
    return dict(kind="ret", score=score, amount=cands[0],
                change=(change or {}).get("scriptpubkey_address"))


# ------------------------------------------------------------------
# Red
# ------------------------------------------------------------------
def http_get(path: str):
    for i in range(3):
        try:
            r = requests.get(f"{API_BASE}{path}", timeout=15)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (429, 502, 503):
                time.sleep(2 * (i + 1))
                continue
            return None
        except Exception:
            time.sleep(1)
    return None


def send_telegram(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message[:4000],
               "parse_mode": "HTML", "disable_web_page_preview": True}
    try:
        r = requests.post(url, json=payload, timeout=15)
        if r.status_code != 200:
            print(f"[Telegram Error] {r.text}")
    except Exception as e:
        print(f"[Telegram Exception] {e}")


def ensure_full(tx: dict) -> dict:
    """Si el websocket no trajo witness, pide la tx completa."""
    if any("witness" not in v for v in tx.get("vin", [])):
        full = http_get(f"/tx/{tx.get('txid')}")
        if full:
            return full
    return tx


# ------------------------------------------------------------------
# SQLite: cuentas y linea de tiempo
# ------------------------------------------------------------------
def db_init(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS addr(
        address TEXT PRIMARY KEY, acct INTEGER NOT NULL, scanned INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS ev(
        acct INTEGER, txid TEXT, addr TEXT, kind TEXT, amount INTEGER, ts INTEGER,
        UNIQUE(txid, addr, kind));
    """)
    c.commit()


def assign_account(c, addrs: list) -> int:
    found = set()
    for a in addrs:
        for (acct,) in c.execute("SELECT acct FROM addr WHERE address=?", (a,)):
            found.add(acct)
    if found:
        target = min(found)
    else:
        target = c.execute("SELECT COALESCE(MAX(acct),0)+1 FROM addr").fetchone()[0]
    for other in found - {target}:
        c.execute("UPDATE addr SET acct=? WHERE acct=?", (target, other))
        c.execute("UPDATE ev SET acct=? WHERE acct=?", (target, other))
    for a in addrs:
        c.execute("INSERT OR IGNORE INTO addr(address, acct) VALUES(?,?)", (a, target))
    c.commit()
    return target


def backfill(c, acct: int, address: str, cur_txid: str):
    known = {r[0] for r in c.execute("SELECT address FROM addr WHERE acct=?", (acct,))}
    for t in (http_get(f"/address/{address}/txs") or [])[:25]:
        tid = t.get("txid")
        if not tid or tid == cur_txid:
            continue
        ts = (t.get("status") or {}).get("block_time") or int(time.time())
        pv = [(i.get("prevout") or {}) for i in t.get("vin", [])]
        spent = sum(p.get("value", 0) for p in pv if p.get("scriptpubkey_address") == address)
        spends_acct = any(p.get("scriptpubkey_address") in known for p in pv)
        recv = [o for o in t.get("vout", []) if o.get("scriptpubkey_address") == address]
        if spent:
            c.execute("INSERT OR IGNORE INTO ev VALUES(?,?,?,?,?,?)",
                      (acct, tid, address, "gasto", spent, ts))
        elif recv and not spends_acct:  # si gasta fondos de la cuenta, es cambio
            o = recv[0]
            kind = "dep_ln" if o.get("scriptpubkey_type") == "v0_p2wsh" else "dep_onchain"
            c.execute("INSERT OR IGNORE INTO ev VALUES(?,?,?,?,?,?)",
                      (acct, tid, address, kind, o.get("value", 0), ts))
    c.execute("UPDATE addr SET scanned=1 WHERE address=?", (address,))
    c.commit()
    time.sleep(0.4)


def timeline(c, acct: int) -> str:
    rows = c.execute(
        "SELECT txid, kind, SUM(amount), MIN(ts) FROM ev WHERE acct=? "
        "GROUP BY txid, kind ORDER BY MIN(ts)", (acct,)).fetchall()
    live_txids = {r[0] for r in rows if r[1] in LIVE_KINDS}
    rows = [r for r in rows if not (r[1] == "gasto" and r[0] in live_txids)]
    lines = []
    for txid, kind, amt, ts in rows[-TIMELINE_N:]:
        when = time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts))
        lines.append(f"• {when} | {KIND_LABEL.get(kind, kind)} | {amt} sats | "
                     f"<code>{txid[:10]}</code>")
    return "\n".join(lines) or "• (sin historial)"


# ------------------------------------------------------------------
# Notificacion
# ------------------------------------------------------------------
def short(a: str) -> str:
    return f"{a[:14]}...{a[-6:]}" if a and len(a) > 22 else (a or "?")


def analyze_and_notify(c, tx: dict):
    tx = ensure_full(tx)
    res = classify(tx)
    if not res or res["score"] < MIN_LEVEL:
        return
    txid, fee = tx.get("txid"), tx.get("fee", 0)

    in_addrs = [(v.get("prevout") or {}).get("scriptpubkey_address") for v in tx["vin"]]
    in_addrs = [a for a in dict.fromkeys(in_addrs) if a]
    acct_addrs = in_addrs + ([res["change"]] if res.get("change") else [])
    acct = assign_account(c, acct_addrs)

    c.execute("INSERT OR IGNORE INTO ev VALUES(?,?,?,?,?,?)",
              (acct, txid, in_addrs[0] if in_addrs else "", res["kind"],
               res["amount"], int(time.time())))
    c.commit()
    todo = [a for a in in_addrs
            if not c.execute("SELECT scanned FROM addr WHERE address=?", (a,)).fetchone()[0]]
    for a in todo[:MAX_ADDR_SCAN]:
        backfill(c, acct, a, txid)

    STATS[res["kind"]] += 1
    lvl = NAME_LEVEL[res["score"]]
    ins = "\n".join(
        f"• {(v.get('prevout') or {}).get('value', 0)} sats ({input_kind(v)}) "
        f"<code>{short((v.get('prevout') or {}).get('scriptpubkey_address'))}</code>"
        for v in tx["vin"])
    outs = "\n".join(
        f"• {o.get('value', 0)} sats → <code>{short(o.get('scriptpubkey_address'))}</code> "
        f"({o.get('scriptpubkey_type')})" for o in tx["vout"])

    msg = (
        f"{ICON_LEVEL[res['score']]} <b>{KIND_LABEL[res['kind']]}</b> — confianza {lvl}\n\n"
        f"<code>{txid}</code>\nhttps://mempool.space/tx/{txid}\n\n"
        f"💰 Monto: <b>{res['amount']} sats</b>\n"
        f"📦 Size: {tx.get('size')} B | Fee: <b>{fee} sats</b>\n"
        f"🧬 v{tx.get('version')} | locktime {tx.get('locktime')} | cuenta #{acct}\n\n"
        f"📥 Inputs:\n{ins}\n\n📤 Outputs:\n{outs}\n\n"
        f"📜 <b>Línea de tiempo cuenta #{acct}</b>\n{timeline(c, acct)}"
    )
    print(f"[MATCH] {txid} | {res['kind']} | {res['amount']} | conf={lvl} | cuenta={acct}")
    send_telegram(msg)

    if sum(STATS.values()) % 20 == 0:
        send_telegram("📊 Resumen: " + ", ".join(f"{KIND_LABEL[k]}: {n}" for k, n in STATS.items()))


def worker():
    c = sqlite3.connect(DB_PATH)  # la conexion vive solo en este hilo
    db_init(c)
    while True:
        tx = NOTIFY_Q.get()
        try:
            analyze_and_notify(c, tx)
        except Exception as e:
            print(f"[Worker Error] {e}")


# ------------------------------------------------------------------
# WebSocket
# ------------------------------------------------------------------
def on_message(ws, message):
    try:
        data = json.loads(message)
    except Exception:
        return
    for tx in data.get("mempool-transactions", {}).get("added", []):
        try:
            txid = tx.get("txid")
            if txid in SEEN_SET or not prefilter(tx):
                continue
            if len(SEEN) == SEEN.maxlen:
                SEEN_SET.discard(SEEN[0])
            SEEN.append(txid)
            SEEN_SET.add(txid)
            NOTIFY_Q.put(tx)
        except Exception as e:
            print(f"[Filter Error] {e}")


def on_error(ws, error):
    print(f"[ERROR] {error}")


def on_open(ws):
    print("[INFO] Conectado")
    send_telegram(
        "🟢 <b>Mempool Bot v12 (Muun) iniciado</b>\n"
        f"• Monto: {MIN_SATS} &lt; x &lt; {MAX_SATS} sats\n"
        f"• Confianza mínima: {NAME_LEVEL[MIN_LEVEL]}\n"
        "• Retiros on-chain, pagos Lightning (swap) y Recovery Tool")
    ws.send(json.dumps({"track-mempool": True}))


def main():
    threading.Thread(target=worker, daemon=True).start()
    while True:
        ws = WebSocketApp(WS_URL, on_open=on_open, on_message=on_message, on_error=on_error)
        ws.run_forever(ping_interval=25, ping_timeout=10)
        print("[INFO] Conexión cerrada. Reconectando en 8s...")
        time.sleep(8)


if __name__ == "__main__":
    print("Iniciando Mempool Bot v12...")
    main()