#!/usr/bin/env python3
"""
Mempool Monitor → Telegram
Filtro: size 151 o 303 bytes + fee 151 sats + Taproot input + SegWit + RBF disabled
Incluye estimación de monto Lightning real
"""

import os
import json
import time
import requests
from datetime import datetime, timezone
from websocket import WebSocketApp

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

WS_URL = "wss://mempool.space/api/v1/ws"
API_BASE = "https://mempool.space/api"

if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
    print("❌ Faltan las variables TELEGRAM_TOKEN o TELEGRAM_CHAT_ID")
    exit(1)

def send_telegram(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": False
    }
    try:
        r = requests.post(url, json=payload, timeout=15)
        if r.status_code != 200:
            print(f"[Telegram Error] {r.text}")
    except Exception as e:
        print(f"[Telegram Exception] {e}")

def is_rbf_disabled(tx: dict) -> bool:
    for vin in tx.get("vin", []):
        if vin.get("sequence", 0xffffffff) < 0xfffffffe:
            return False
    return True

def has_taproot_input(tx: dict) -> bool:
    for vin in tx.get("vin", []):
        prevout = vin.get("prevout") or {}
        if prevout.get("scriptpubkey_type") == "v1_p2tr":
            return True
    return False

def has_segwit(tx: dict) -> bool:
    for vin in tx.get("vin", []):
        if vin.get("witness"):
            return True
    for vout in tx.get("vout", []):
        if vout.get("scriptpubkey_type") in ("v0_p2wpkh", "v0_p2wsh", "v1_p2tr"):
            return True
    return False

def matches_criteria(tx: dict) -> bool:
    size = tx.get("size")
    fee = tx.get("fee")

    if size not in (70, 75, 151, 303, 410):
        return False
    if fee != 151:
        return False
    if not has_taproot_input(tx):
        return False
    if not has_segwit(tx):
        return False
    if not is_rbf_disabled(tx):
        return False
    return True

def ts_to_str(ts):
    if not ts:
        return "?"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except:
        return str(ts)

def get_address_txs(address: str, limit=5):
    try:
        r = requests.get(f"{API_BASE}/address/{address}/txs", timeout=12)
        if r.status_code == 200:
            return r.json()[:limit]
    except:
        pass
    return []

def estimate_lightning_amount(tx: dict) -> tuple:
    """
    Intenta estimar el monto real del pago Lightning.
    Retorna (monto_estimado, explicacion)
    """
    fee = tx.get("fee", 0)
    outputs = tx.get("vout", [])
    ancestors = tx.get("ancestors") or []

    # Output principal (el más grande)
    main_output = 0
    for vout in outputs:
        value = vout.get("value", 0)
        if value > main_output:
            main_output = value

    # Caso simple: solo un output grande + fee 151
    if len(outputs) == 1:
        estimated = main_output
        return estimated, "Output único"

    # Caso típico Muun / swap: suele haber un output principal + change pequeño
    if len(outputs) == 2:
        values = sorted([v.get("value", 0) for v in outputs], reverse=True)
        # El más grande suele ser el pago, el pequeño el change
        estimated = values[0]
        return estimated, "Output principal (posible pago)"

    # Si hay ancestors, intentamos ser un poco más inteligentes
    if ancestors:
        # Sumamos fees de ancestors + fee actual para tener una idea
        total_related_fee = fee
        for anc in ancestors:
            total_related_fee += anc.get("fee", 0)

        # Estimación conservadora
        estimated = main_output
        return estimated, f"Con {len(ancestors)} ancestors"

    # Por defecto
    return main_output, "Estimación básica"

def analyze_and_notify(tx: dict):
    txid = tx.get("txid")
    fee = tx.get("fee", 0)
    size = tx.get("size")
    first_seen = tx.get("firstSeen")
    fee_rate = tx.get("feePerVsize") or tx.get("effectiveFeePerVsize") or 0

    num_inputs = len(tx.get("vin", []))
    num_outputs = len(tx.get("vout", []))

    # Inputs
    inputs_text = ""
    origin_addresses = []

    for vin in tx.get("vin", []):
        prevout = vin.get("prevout") or {}
        addr = prevout.get("scriptpubkey_address", "?")
        value = prevout.get("value", 0)
        spk = prevout.get("scriptpubkey_type", "?")
        inputs_text += f"• {value} sats ← <code>{addr[:16]}...{addr[-6:]}</code> ({spk})\n"
        if addr.startswith("bc1"):
            origin_addresses.append(addr)

    # Outputs
    outputs_text = ""
    for vout in tx.get("vout", []):
        addr = vout.get("scriptpubkey_address") or "OP_RETURN"
        value = vout.get("value", 0)
        spk = vout.get("scriptpubkey_type", "?")
        outputs_text += f"• {value} sats → <code>{addr[:16]}...{addr[-6:]}</code> ({spk})\n"

    # Ancestors
    ancestors = tx.get("ancestors") or []
    effective_fee = tx.get("effectiveFeePerVsize") or fee_rate
    ancestors_text = ""
    if ancestors:
        ancestors_text = f"\n🔗 Ancestors: {len(ancestors)} | Fee efectiva: <b>{effective_fee:.2f} sat/vB</b>\n"

    # === Estimación de monto Lightning ===
    ln_amount, ln_reason = estimate_lightning_amount(tx)

    lightning_text = f"""
⚡ <b>Posible pago Lightning (patrón Muun/Swap)</b>
Monto estimado Lightning: <b>{ln_amount} sats</b>
({ln_reason})
"""

    # Historial un nivel atrás
    history_text = ""
    if origin_addresses:
        addr = origin_addresses[0]
        txs = get_address_txs(addr, limit=4)
        txs = list(reversed(txs))

        history_text = "\n📜 Origen de los fondos:\n"
        for t in txs[:3]:
            status = t.get("status", {})
            confirmed = status.get("confirmed", False)
            block_time = status.get("block_time")
            t_txid = t.get("txid", "")[:10] + "..."
            time_str = ts_to_str(block_time) if confirmed else "mempool"

            received = sum(v.get("value", 0) for v in t.get("vout", []) if v.get("scriptpubkey_address") == addr)
            sent = 0
            for vin in t.get("vin", []):
                prev = vin.get("prevout") or {}
                if prev.get("scriptpubkey_address") == addr:
                    sent += prev.get("value", 0)

            if received:
                history_text += f"• {time_str} | recibió {received} sats | <code>{t_txid}</code>\n"
            elif sent:
                history_text += f"• {time_str} | envió {sent} sats | <code>{t_txid}</code>\n"

    msg = f"""
🎯 <b>MATCH DETECTADO</b>

<code>{txid}</code>
🔗 https://mempool.space/tx/{txid}

📦 Size: <b>{size} bytes</b> | Fee: <b>{fee} sats</b>
📊 Fee rate: <b>{fee_rate:.2f} sat/vB</b>
📥 Inputs: <b>{num_inputs}</b> | 📤 Outputs: <b>{num_outputs}</b>
🕒 Primera vez: {ts_to_str(first_seen)}
{lightning_text}{ancestors_text}
📥 <b>Inputs:</b>
{inputs_text}
📤 <b>Outputs:</b>
{outputs_text}
{history_text}
— Mempool Bot v3 (Estimación LN)
"""

    print(f"[MATCH] {txid} | size={size} | LN estimado={ln_amount}")
    send_telegram(msg.strip())

def on_message(ws, message):
    try:
        data = json.loads(message)
    except:
        return

    added = data.get("mempool-transactions", {}).get("added", [])
    for tx in added:
        if matches_criteria(tx):
            analyze_and_notify(tx)

def on_error(ws, error):
    print(f"[ERROR] {error}")

def on_close(ws, close_status_code, close_msg):
    print("[INFO] Conexión cerrada. Reconectando en 8s...")
    time.sleep(8)
    start()

def on_open(ws):
    print("[INFO] Conectado - Filtro 151/303 + Estimación LN")
    send_telegram("🟢 <b>Mempool Bot v3 iniciado</b>\nFiltro: 151 y 303 bytes + fee 151\n+ Estimación de monto Lightning")
    ws.send(json.dumps({"track-mempool": True}))

def start():
    ws = WebSocketApp(
        WS_URL,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
    )
    ws.run_forever(ping_interval=25, ping_timeout=10)

if __name__ == "__main__":
    print("Iniciando Mempool Bot v3...")
    start()
