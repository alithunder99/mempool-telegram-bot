#!/usr/bin/env python3
"""
Mempool Monitor → Telegram
Patrón: size=151 + fee=151 + Taproot input + SegWit + RBF disabled
"""

import os
import json
import time
import requests
from datetime import datetime, timezone
from websocket import WebSocketApp

# ====================== CONFIGURACIÓN ======================
TELEGRAM_TOKEN = os.getenv("")
TELEGRAM_CHAT_ID = os.getenv("")

WS_URL = "wss://mempool.space/api/v1/ws"
API_BASE = "https://mempool.space/api"

if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
    print("❌ Faltan las variables TELEGRAM_TOKEN o TELEGRAM_CHAT_ID")
    exit(1)

# ====================== TELEGRAM ======================

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

# ====================== FILTROS ======================

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
    if tx.get("size") != 151:
        return False
    if tx.get("fee") != 151:
        return False
    if not has_taproot_input(tx):
        return False
    if not has_segwit(tx):
        return False
    if not is_rbf_disabled(tx):
        return False
    return True

# ====================== UTILIDADES ======================

def ts_to_str(ts):
    if not ts:
        return "desconocido"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except:
        return str(ts)

def get_address_txs(address: str, limit=8):
    try:
        r = requests.get(f"{API_BASE}/address/{address}/txs", timeout=12)
        if r.status_code == 200:
            return r.json()[:limit]
    except:
        pass
    return []

# ====================== ANÁLISIS + MENSAJE ======================

def analyze_and_notify(tx: dict):
    txid = tx.get("txid")
    fee = tx.get("fee")
    size = tx.get("size")
    first_seen = tx.get("firstSeen")

    # Inputs
    inputs_text = ""
    origin_addresses = []
    for i, vin in enumerate(tx.get("vin", [])):
        prevout = vin.get("prevout") or {}
        addr = prevout.get("scriptpubkey_address", "?")
        value = prevout.get("value", 0)
        spk = prevout.get("scriptpubkey_type", "?")
        inputs_text += f"• {value} sats ← <code>{addr}</code> ({spk})\n"
        if addr.startswith("bc1"):
            origin_addresses.append(addr)

    # Outputs
    outputs_text = ""
    for vout in tx.get("vout", []):
        addr = vout.get("scriptpubkey_address") or "OP_RETURN"
        value = vout.get("value", 0)
        spk = vout.get("scriptpubkey_type", "?")
        outputs_text += f"• {value} sats → <code>{addr}</code> ({spk})\n"

    # Historial corto de la primera dirección de origen
    history_text = ""
    if origin_addresses:
        addr = origin_addresses[0]
        txs = get_address_txs(addr, limit=6)
        txs = list(reversed(txs))  # más antigua primero

        for t in txs:
            status = t.get("status", {})
            confirmed = status.get("confirmed", False)
            block_time = status.get("block_time")
            t_txid = t.get("txid", "")[:12] + "..."
            time_str = ts_to_str(block_time) if confirmed else "mempool"

            # Calcular si recibió o envió
            received = sum(v.get("value", 0) for v in t.get("vout", []) if v.get("scriptpubkey_address") == addr)
            sent = 0
            for vin in t.get("vin", []):
                prev = vin.get("prevout") or {}
                if prev.get("scriptpubkey_address") == addr:
                    sent += prev.get("value", 0)

            movement = ""
            if received:
                movement = f"recibió {received} sats"
            if sent:
                movement = f"envió {sent} sats"

            history_text += f"• {time_str} | {movement} | <code>{t_txid}</code>\n"

    # Construir mensaje
    msg = f"""
🎯 <b>MATCH DETECTADO</b>

<b>TXID:</b> <code>{txid}</code>
🔗 https://mempool.space/tx/{txid}

<b>Size:</b> {size} bytes
<b>Fee:</b> {fee} sats
<b>Primera vez vista:</b> {ts_to_str(first_seen)}

📥 <b>Inputs:</b>
{inputs_text}
📤 <b>Outputs:</b>
{outputs_text}
"""

    if history_text:
        msg += f"\n📜 <b>Historial reciente de origen:</b>\n{history_text}"

    msg += "\n— Mempool Bot"

    print(f"[MATCH] {txid}")
    send_telegram(msg.strip())

# ====================== WEBSOCKET ======================

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
    print("[INFO] Conexión cerrada. Reconectando en 8 segundos...")
    time.sleep(8)
    start()

def on_open(ws):
    print("[INFO] Conectado a mempool.space")
    send_telegram("🟢 <b>Mempool Bot iniciado</b>\nEscuchando transacciones...")
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
    print("Iniciando Mempool Bot...")
    start()
