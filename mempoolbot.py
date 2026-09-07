#!/usr/bin/env python3
"""
Mempool Monitor → Telegram
Filtro: fee 70/75/151/303/410/412 sats
+ Taproot + SegWit + RBF disabled
+ Sin OP_RETURN
+ Fingerprinting heurístico de patrones Muun / Submarine Swaps Lightning
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

def has_op_return(tx: dict) -> bool:
    """Devuelve True si la transacción tiene alguna salida OP_RETURN"""
    for vout in tx.get("vout", []):
        script_type = vout.get("scriptpubkey_type", "")
        if script_type == "op_return" or script_type == "nulldata":
            return True
        # También revisamos el scriptpubkey por si acaso
        script = vout.get("scriptpubkey", "")
        if script.startswith("6a"):  # OP_RETURN en hex
            return True
    return False

# ============================================================
# Fingerprinting heurístico de Muun / Submarine Swaps
# Basado en investigación pública de wallet fingerprinting
# (p.ej. estudios de Belcher / AntoineFerron sobre Muun).
# ⚠️ Esto es una heurística de patrones estructurales de script,
# NO una certeza absoluta. Puede producir falsos positivos y
# NO permite inferir identidad, ubicación geográfica ni IP.
# ============================================================

# Contador en memoria de matches por familia de fee.
# Solo estadísticas agregadas de patrones de transacción.
FEE_STATS = {
    70: {"total": 0, "muun": 0},
    75: {"total": 0, "muun": 0},
    151: {"total": 0, "muun": 0},
    303: {"total": 0, "muun": 0},
    410: {"total": 0, "muun": 0},
    412: {"total": 0, "muun": 0},
}
MATCH_COUNT = 0


def detect_muun_pattern(tx: dict) -> tuple:
    """
    Heurística para reconocer transacciones típicas de Muun wallet.

    Muun usa:
      - P2WSH con estructura tipo HTLC (hashlock + timelock) cuando
        el fondo proviene de/hacia un submarine swap Lightning.
      - P2WPKH "normal" cuando no hay swap involucrado.

    Señales que buscamos (no concluyentes por sí solas):
      - scriptpubkey_type "v0_p2wsh" en los prevouts de los inputs.
      - Witness con varios elementos en el stack (firma + preimage +
        script de redención), típico de scripts HTLC.
      - Tamaño del witness script coherente con un HTLC (más grande
        que un simple P2WPKH firmado).

    Devuelve: (score: int 0-100, razon: str)
    """
    score = 0
    razones = []

    p2wsh_inputs = 0
    htlc_like_witness = 0
    total_inputs = 0

    for vin in tx.get("vin", []):
        prevout = vin.get("prevout") or {}
        spk_type = prevout.get("scriptpubkey_type", "")
        witness = vin.get("witness") or []
        total_inputs += 1

        if spk_type == "v0_p2wsh":
            p2wsh_inputs += 1

        # Un P2WPKH normal tiene witness de 2 elementos: [firma, pubkey].
        # Un HTLC típico (submarine swap) suele tener 3+ elementos:
        # [firma, preimage/OP_0, redeem_script], y el redeem_script
        # (último elemento) suele ser notablemente más largo (>100 bytes hex).
        if len(witness) >= 3:
            redeem_script = witness[-1] if witness else ""
            if isinstance(redeem_script, str) and len(redeem_script) > 100:
                htlc_like_witness += 1

    if total_inputs == 0:
        return 0, "Sin inputs analizables"

    if p2wsh_inputs > 0:
        score += 40
        razones.append(f"{p2wsh_inputs}/{total_inputs} inputs P2WSH")

    if htlc_like_witness > 0:
        score += 45
        razones.append(f"{htlc_like_witness} witness con estructura tipo HTLC")

    # Muun también usa outputs P2WSH para depósitos de swap-in en curso.
    p2wsh_outputs = sum(
        1 for v in tx.get("vout", []) if v.get("scriptpubkey_type") == "v0_p2wsh"
    )
    if p2wsh_outputs > 0:
        score += 15
        razones.append(f"{p2wsh_outputs} outputs P2WSH")

    score = min(score, 100)
    razon = "; ".join(razones) if razones else "Sin señales de patrón Muun/HTLC"
    return score, razon


def classify_swap_direction(tx: dict) -> tuple:
    """
    Clasifica heurísticamente la dirección de un posible submarine swap:
      - "swap-in": el usuario envía fondos on-chain para recibir Lightning
        (input propio → output tipo HTLC/P2WSH, depósito en curso).
      - "swap-out": el usuario recibe fondos on-chain tras una operación
        Lightning (input tipo HTLC/P2WSH → output propio, retiro liquidado).
      - "indeterminado": no hay señales suficientes para decidir.

    Esta clasificación es heurística y estructural, basada solo en el
    flujo de valor y la presencia de scripts HTLC. No infiere identidad
    ni ubicación de las partes involucradas.
    """
    try:
        inputs_p2wsh = 0
        inputs_htlc = 0
        for vin in tx.get("vin", []):
            prevout = vin.get("prevout") or {}
            witness = vin.get("witness") or []
            if prevout.get("scriptpubkey_type") == "v0_p2wsh":
                inputs_p2wsh += 1
            if len(witness) >= 3:
                redeem_script = witness[-1] if witness else ""
                if isinstance(redeem_script, str) and len(redeem_script) > 100:
                    inputs_htlc += 1

        outputs_p2wsh = sum(
            1 for v in tx.get("vout", []) if v.get("scriptpubkey_type") == "v0_p2wsh"
        )

        # Si el HTLC se está "gastando" desde un input (liquidando el swap),
        # y el output es una dirección normal (p2wpkh/p2tr), parece un
        # retiro (swap-out): los fondos Lightning ya se convirtieron a on-chain.
        if inputs_htlc > 0 and outputs_p2wsh == 0:
            return "swap-out", (
                f"{inputs_htlc} input(s) liquidan un script HTLC hacia "
                "una dirección normal (posible retiro Lightning→on-chain)"
            )

        # Si el output es P2WSH (se está creando un HTLC) y los inputs son
        # direcciones normales, parece un depósito en curso (swap-in).
        if outputs_p2wsh > 0 and inputs_htlc == 0:
            return "swap-in", (
                f"{outputs_p2wsh} output(s) crean un script P2WSH/HTLC "
                "(posible depósito on-chain→Lightning en curso)"
            )

        if inputs_p2wsh > 0 or outputs_p2wsh > 0:
            return "indeterminado", "Hay P2WSH pero el flujo no es concluyente"

        return "indeterminado", "Sin señales de submarine swap"
    except Exception as e:
        return "indeterminado", f"Error al clasificar: {e}"


def update_fee_stats(fee: int, muun_score: int):
    """Actualiza contadores agregados por familia de fee. Solo estadísticas
    de patrones de transacción; no almacena IP, ubicación ni datos personales."""
    global MATCH_COUNT
    if fee in FEE_STATS:
        FEE_STATS[fee]["total"] += 1
        if muun_score >= 50:
            FEE_STATS[fee]["muun"] += 1
    MATCH_COUNT += 1


def build_fee_stats_summary() -> str:
    lines = ["📊 <b>Resumen agregado por familia de fee</b>"]
    for fee_val, stats in FEE_STATS.items():
        lines.append(
            f"• {fee_val} sats → {stats['total']} matches | "
            f"{stats['muun']} con patrón Muun (score≥50)"
        )
    return "\n".join(lines)

def matches_criteria(tx: dict) -> bool:
    fee = tx.get("fee")

    # Comisión total pagada
    if fee not in (70, 75, 151, 303, 410, 412):
        return False

    # Características requeridas
    if not has_taproot_input(tx):
        return False
    if not has_segwit(tx):
        return False
    if not is_rbf_disabled(tx):
        return False

    # Excluir transacciones con OP_RETURN
    if has_op_return(tx):
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
    outputs = tx.get("vout", [])
    ancestors = tx.get("ancestors") or []

    main_output = 0
    for vout in outputs:
        value = vout.get("value", 0)
        if value > main_output:
            main_output = value

    if len(outputs) == 1:
        return main_output, "Output único"

    if len(outputs) == 2:
        values = sorted([v.get("value", 0) for v in outputs], reverse=True)
        return values[0], "Output principal (posible pago)"

    if ancestors:
        return main_output, f"Con {len(ancestors)} ancestors"

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

    # Estimación Lightning
    ln_amount, ln_reason = estimate_lightning_amount(tx)

    lightning_text = f"""
⚡ <b>Posible pago Lightning (patrón Muun/Swap)</b>
Monto estimado Lightning: <b>{ln_amount} sats</b>
({ln_reason})
"""

    # Fingerprinting Muun / clasificación de swap (heurístico, con protección)
    muun_score, muun_reason = 0, "No evaluado"
    swap_direction, swap_reason = "indeterminado", "No evaluado"
    try:
        muun_score, muun_reason = detect_muun_pattern(tx)
    except Exception as e:
        muun_reason = f"Error en heurística Muun: {e}"
    try:
        swap_direction, swap_reason = classify_swap_direction(tx)
    except Exception as e:
        swap_reason = f"Error en clasificación de swap: {e}"

    try:
        update_fee_stats(fee, muun_score)
    except Exception:
        pass

    fingerprint_text = f"""
🔍 <b>Fingerprint Muun</b>: {muun_score}/100
   ({muun_reason})
🔁 <b>Dirección swap</b>: <b>{swap_direction}</b>
   ({swap_reason})
"""

    # Historial
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
{lightning_text}{fingerprint_text}{ancestors_text}
📥 <b>Inputs:</b>
{inputs_text}
📤 <b>Outputs:</b>
{outputs_text}
{history_text}
— Mempool Bot v10 (Muun/Swap fingerprinting)
"""

    print(f"[MATCH] {txid} | size={size} | fee={fee} | LN estimado={ln_amount} | Muun={muun_score} | swap={swap_direction}")
    send_telegram(msg.strip())

    # Resumen agregado cada 20 matches
    try:
        if MATCH_COUNT % 20 == 0:
            send_telegram(build_fee_stats_summary())
    except Exception:
        pass

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
    print("[INFO] Conectado - Fee filter + Sin OP_RETURN + Muun fingerprinting")
    send_telegram(
        "🟢 <b>Mempool Bot v10 iniciado</b>\n"
        "Filtro activo:\n"
        "• Fee: <b>70 / 75 / 151 / 303 / 410 / 412 sats</b>\n"
        "• Taproot + SegWit + RBF off\n"
        "• <b>Sin OP_RETURN</b>\n"
        "• Fingerprinting heurístico de patrones Muun/Swap"
    )
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
    print("Iniciando Mempool Bot v10...")
    start()
