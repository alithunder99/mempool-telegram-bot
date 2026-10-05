#!/usr/bin/env python3
"""
Mempool Monitor → Telegram  (v11, Muun only)

Filtros estrictos:
  - Fee total: 151 o 303 sats
  - Al menos un input Taproot + SegWit + RBF desactivado + sin OP_RETURN
  - Monto del pago: MIN_SATS < monto < MAX_SATS (por defecto 600 < x < 30000)
Lógica Muun / submarine swap:
  - Un pago Lightning saliente de Muun es una tx on-chain que crea un output
    P2WSH (HTLC del swap). Ese output se usa como "monto del pago".
  - Si no hay output P2WSH, se trata como pago on-chain normal.
  - Regla de la Recovery Tool: fee 151 si monto < 20k, fee 303 si monto >= 20k.
Heurística: NO es certeza absoluta, puede haber falsos positivos.
"""

import os
import json
import time
import queue
import threading
from collections import deque
from datetime import datetime, timezone

import requests
from websocket import WebSocketApp

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

WS_URL = "wss://mempool.space/api/v1/ws"
API_BASE = "https://mempool.space/api"

ALLOWED_FEES = (151, 303)
MIN_SATS = int(os.getenv("MIN_SATS", "600"))      # estricto: monto > MIN_SATS
MAX_SATS = int(os.getenv("MAX_SATS", "30000"))    # estricto: monto < MAX_SATS
FEE_SPLIT = int(os.getenv("FEE_SPLIT", "20000"))  # 151 por debajo, 303 desde aquí

if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
    print("❌ Faltan las variables TELEGRAM_TOKEN o TELEGRAM_CHAT_ID")
    raise SystemExit(1)

FEE_STATS = {f: {"total": 0, "muun": 0} for f in ALLOWED_FEES}
MATCH_COUNT = 0
SEEN = deque(maxlen=5000)
SEEN_SET = set()
NOTIFY_Q = queue.Queue()


# ------------------------------------------------------------------
# Telegram
# ------------------------------------------------------------------
def send_telegram(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": False,
    }
    try:
        r = requests.post(url, json=payload, timeout=15)
        if r.status_code != 200:
            print(f"[Telegram Error] {r.text}")
    except Exception as e:
        print(f"[Telegram Exception] {e}")


# ------------------------------------------------------------------
# Filtros básicos
# ------------------------------------------------------------------
def is_rbf_disabled(tx: dict) -> bool:
    return all(v.get("sequence", 0xffffffff) >= 0xfffffffe for v in tx.get("vin", []))


def has_taproot_input(tx: dict) -> bool:
    return any(
        (v.get("prevout") or {}).get("scriptpubkey_type") == "v1_p2tr"
        for v in tx.get("vin", [])
    )


def has_segwit(tx: dict) -> bool:
    if any(v.get("witness") for v in tx.get("vin", [])):
        return True
    return any(
        v.get("scriptpubkey_type") in ("v0_p2wpkh", "v0_p2wsh", "v1_p2tr")
        for v in tx.get("vout", [])
    )


def has_op_return(tx: dict) -> bool:
    for v in tx.get("vout", []):
        if v.get("scriptpubkey_type") in ("op_return", "nulldata"):
            return True
        if v.get("scriptpubkey", "").startswith("6a"):
            return True
    return False


# ------------------------------------------------------------------
# Lógica de pago / submarine swap
# ------------------------------------------------------------------
def swap_outputs(tx: dict) -> list:
    """Outputs P2WSH = posible HTLC de un submarine swap (pago Lightning)."""
    return [v for v in tx.get("vout", []) if v.get("scriptpubkey_type") == "v0_p2wsh"]


def payment_candidates(tx: dict) -> tuple:
    """Devuelve (outputs candidatos a ser el pago, tipo)."""
    swaps = swap_outputs(tx)
    if swaps:
        return swaps, "swap (pago Lightning)"
    return tx.get("vout", []), "on-chain"


def amount_in_range(value: int) -> bool:
    return MIN_SATS < value < MAX_SATS


def payment_hits(tx: dict) -> tuple:
    cands, kind = payment_candidates(tx)
    hits = [v for v in cands if amount_in_range(v.get("value", 0))]
    return hits, kind


def withdrawal_amount(tx: dict) -> int:
    """Monto del retiro = suma de outputs (la Recovery Tool barre todo a un destino)."""
    return sum(v.get("value", 0) for v in tx.get("vout", []))


def fee_matches_amount(fee: int, amount: int) -> bool:
    """Regla fija de la Recovery Tool: 151 sats si < 20k, 303 sats si >= 20k."""
    if not amount_in_range(amount):
        return False
    if fee == 151:
        return amount < FEE_SPLIT
    if fee == 303:
        return amount >= FEE_SPLIT
    return False


def matches_criteria(tx: dict) -> bool:
    fee = tx.get("fee")
    if fee not in ALLOWED_FEES:
        return False
    if not fee_matches_amount(fee, withdrawal_amount(tx)):
        return False
    if not has_taproot_input(tx):
        return False
    if not has_segwit(tx):
        return False
    if not is_rbf_disabled(tx):
        return False
    if has_op_return(tx):
        return False
    return True


def muun_score(tx: dict) -> tuple:
    """Score 0-100 sobre la forma de la tx de creación de swap.
    Nota: el script HTLC dentro del P2WSH NO es visible hasta que se gasta,
    por eso solo se puede puntuar la estructura externa de la tx."""
    score, reasons = 0, []
    vins = tx.get("vin", [])
    vouts = tx.get("vout", [])
    if not vins:
        return 0, "Sin inputs"

    types = [(v.get("prevout") or {}).get("scriptpubkey_type") for v in vins]
    if all(t == "v1_p2tr" for t in types):
        score += 30
        reasons.append("todos los inputs P2TR")
        if all(len(v.get("witness") or []) == 1 for v in vins):
            score += 20
            reasons.append("key-path (1 elemento de witness)")

    swaps = swap_outputs(tx)
    if len(swaps) == 1:
        score += 25
        reasons.append("1 output P2WSH (posible HTLC swap)")
        others = [v for v in vouts if v.get("scriptpubkey_type") != "v0_p2wsh"]
        if len(others) == 0:
            score += 10
            reasons.append("sin cambio")
        elif len(others) == 1 and others[0].get("scriptpubkey_type") == "v1_p2tr":
            score += 10
            reasons.append("cambio P2TR")

    score = min(score, 100)
    return score, "; ".join(reasons) or "Sin señales"


# ------------------------------------------------------------------
# Utilidades de mensaje
# ------------------------------------------------------------------
def ts_to_str(ts):
    if not ts:
        return "?"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(ts)


def short(addr: str) -> str:
    return f"{addr[:16]}...{addr[-6:]}" if len(addr) > 24 else addr


def get_address_txs(address: str, limit=5):
    try:
        r = requests.get(f"{API_BASE}/address/{address}/txs", timeout=12)
        if r.status_code == 200:
            return r.json()[:limit]
    except Exception:
        pass
    return []


def build_fee_stats_summary() -> str:
    lines = ["📊 <b>Resumen por fee</b>"]
    for fee_val, s in FEE_STATS.items():
        lines.append(f"• {fee_val} sats → {s['total']} matches | {s['muun']} con score≥50")
    return "\n".join(lines)


def analyze_and_notify(tx: dict):
    global MATCH_COUNT
    txid = tx.get("txid")
    fee = tx.get("fee", 0)
    size = tx.get("size")
    fee_rate = tx.get("feePerVsize") or tx.get("effectiveFeePerVsize") or 0

    _, kind = payment_candidates(tx)
    amount = withdrawal_amount(tx)
    score, reason = muun_score(tx)

    if fee in FEE_STATS:
        FEE_STATS[fee]["total"] += 1
        if score >= 50:
            FEE_STATS[fee]["muun"] += 1
    MATCH_COUNT += 1

    inputs_text, origin = "", []
    for vin in tx.get("vin", []):
        p = vin.get("prevout") or {}
        addr = p.get("scriptpubkey_address", "?")
        inputs_text += f"• {p.get('value', 0)} sats ← <code>{short(addr)}</code> ({p.get('scriptpubkey_type', '?')})\n"
        if addr.startswith("bc1"):
            origin.append(addr)

    outputs_text = ""
    for v in tx.get("vout", []):
        addr = v.get("scriptpubkey_address") or "?"
        outputs_text += f"• {v.get('value', 0)} sats → <code>{short(addr)}</code> ({v.get('scriptpubkey_type', '?')})\n"

    seqs = sorted({hex(v.get("sequence", 0)) for v in tx.get("vin", [])})
    raw_info = f"version={tx.get('version')} | locktime={tx.get('locktime')} | sequence={', '.join(seqs)}"

    history_text = ""
    if origin:
        txs = list(reversed(get_address_txs(origin[0], limit=4)))
        if txs:
            history_text = "\n📜 Origen de los fondos:\n"
        for t in txs[:3]:
            st = t.get("status", {})
            when = ts_to_str(st.get("block_time")) if st.get("confirmed") else "mempool"
            addr = origin[0]
            recv = sum(o.get("value", 0) for o in t.get("vout", []) if o.get("scriptpubkey_address") == addr)
            sent = sum((i.get("prevout") or {}).get("value", 0) for i in t.get("vin", [])
                       if (i.get("prevout") or {}).get("scriptpubkey_address") == addr)
            verb, val = ("recibió", recv) if recv else ("envió", sent)
            history_text += f"• {when} | {verb} {val} sats | <code>{t.get('txid', '')[:10]}...</code>\n"

    msg = f"""
🎯 <b>MATCH MUUN</b> — {kind}

<code>{txid}</code>
🔗 https://mempool.space/tx/{txid}

💰 Monto del retiro: <b>{amount} sats</b>
📦 Size: <b>{size} bytes</b> | Fee: <b>{fee} sats</b> ({fee_rate:.2f} sat/vB)
🔍 Score Muun: <b>{score}/100</b>
   ({reason})
🧬 {raw_info}

📥 <b>Inputs:</b>
{inputs_text}
📤 <b>Outputs:</b>
{outputs_text}{history_text}
— Mempool Bot v11 (Muun only)
"""
    print(f"[MATCH] {txid} | fee={fee} | monto={amount} | {kind} | score={score}")
    send_telegram(msg.strip())

    if MATCH_COUNT % 20 == 0:
        send_telegram(build_fee_stats_summary())


def worker():
    """Procesa notificaciones fuera del hilo del websocket (evita bloquearlo)."""
    while True:
        tx = NOTIFY_Q.get()
        try:
            analyze_and_notify(tx)
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
            if txid in SEEN_SET:
                continue
            if matches_criteria(tx):
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
    print("[INFO] Conectado - Muun only (fee 151/303, 600-30000 sats)")
    send_telegram(
        "🟢 <b>Mempool Bot v11 iniciado</b>\n"
        f"• Fee: <b>{' / '.join(map(str, ALLOWED_FEES))} sats</b>\n"
        f"• Monto: <b>{MIN_SATS} &lt; x &lt; {MAX_SATS} sats</b>\n"
        "• Taproot + SegWit + RBF off + sin OP_RETURN\n"
        f"• 151 sats si &lt; {FEE_SPLIT} | 303 sats si ≥ {FEE_SPLIT} (Recovery Tool)"
    )
    ws.send(json.dumps({"track-mempool": True}))


def main():
    threading.Thread(target=worker, daemon=True).start()
    while True:  # reconexión en bucle (sin recursión)
        ws = WebSocketApp(WS_URL, on_open=on_open, on_message=on_message, on_error=on_error)
        ws.run_forever(ping_interval=25, ping_timeout=10)
        print("[INFO] Conexión cerrada. Reconectando en 8s...")
        time.sleep(8)


if __name__ == "__main__":
    print("Iniciando Mempool Bot v11...")
    main()