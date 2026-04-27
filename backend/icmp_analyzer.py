"""ICMP steganography analyzer."""
import re
from typing import List, Dict
from fastapi import FastAPI, HTTPException
from backend.session import get_session


def _safe_ascii(data: bytes) -> str:
    if not data:
        return ""
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data)


def _detect_tunnel(data: bytes) -> List[str]:
    """Detect if ICMP payload looks like a tunneled protocol."""
    hints = []
    if len(data) >= 20:
        # Check for IP packet inside ICMP payload
        version = data[0] >> 4
        if version == 4 or version == 6:
            hints.append("Possible IP-in-ICMP tunnel")
        # Check for HTTP-like text
        text = data[:256].decode("utf-8", errors="ignore")
        if text.startswith(("GET ", "POST ", "HTTP/")):
            hints.append("Possible HTTP-in-ICMP tunnel")
        # Check for common strings
        if b"password" in data.lower() or b"flag" in data.lower():
            hints.append("Suspicious keywords in payload")
    return hints


def analyze(session: dict) -> dict:
    packets = session["packets"]
    icmp_packets = []
    for p in packets:
        if p.get("protocol") == "ICMP":
            icmp = p.get("layers", {}).get("icmp", {})
            icmp_packets.append({
                "index": p["index"],
                "type": icmp.get("type"),
                "code": icmp.get("code"),
                "id": icmp.get("id"),
                "seq": icmp.get("seq"),
                "payload_hex": icmp.get("payload_hex", ""),
                "payload_ascii": icmp.get("payload_ascii", ""),
                "src": p.get("src", ""),
                "dst": p.get("dst", ""),
            })

    # Extract data by different dimensions
    by_seq = []
    by_code = []
    by_id = []
    by_len = []
    data_bytes = []
    tunnel_hints = []

    for pkt in icmp_packets:
        if pkt["type"] == 8 or pkt["type"] == 0:
            if pkt["seq"] is not None:
                by_seq.append({"seq": pkt["seq"], "hex": pkt["payload_hex"], "ascii": pkt["payload_ascii"]})
            if pkt["code"] is not None:
                by_code.append({"code": pkt["code"], "hex": pkt["payload_hex"], "ascii": pkt["payload_ascii"]})
            if pkt["id"] is not None:
                by_id.append({"id": pkt["id"], "hex": pkt["payload_hex"], "ascii": pkt["payload_ascii"]})
            if pkt["payload_hex"]:
                payload_bytes = bytes.fromhex(pkt["payload_hex"])
                data_bytes.append(payload_bytes)
                by_len.append({"len": len(payload_bytes), "hex": pkt["payload_hex"], "ascii": pkt["payload_ascii"]})
                hints = _detect_tunnel(payload_bytes)
                if hints:
                    tunnel_hints.append({"index": pkt["index"], "hints": hints})

    # Reconstruct hidden data from payloads
    reconstructed = b""
    for db in data_bytes:
        if len(db) > 0:
            reconstructed += db

    # Try to extract data from seq numbers (common steganography: seq low byte = char)
    seq_ascii = ""
    for item in by_seq:
        seq = item["seq"]
        if seq is not None and 32 <= (seq & 0xFF) < 127:
            seq_ascii += chr(seq & 0xFF)

    # Try to extract data from code values
    code_ascii = ""
    for item in by_code:
        code = item["code"]
        if code is not None and 32 <= code < 127:
            code_ascii += chr(code)

    # Try to extract data from payload lengths
    len_ascii = ""
    for item in by_len:
        l = item["len"]
        if 32 <= l < 127:
            len_ascii += chr(l)

    # Try to extract data from first byte of each payload
    first_bytes = b""
    for db in data_bytes:
        if len(db) > 0:
            first_bytes += bytes([db[0]])

    return {
        "count": len(icmp_packets),
        "packets": icmp_packets[:100],
        "by_seq": by_seq[:100],
        "by_code": by_code[:100],
        "by_id": by_id[:100],
        "by_len": by_len[:100],
        "reconstructed_hex": reconstructed.hex(),
        "reconstructed_ascii": _safe_ascii(reconstructed),
        "reconstructed_text": reconstructed.decode("utf-8", errors="ignore") if reconstructed else "",
        "seq_ascii": seq_ascii[:500],
        "code_ascii": code_ascii[:500],
        "len_ascii": len_ascii[:500],
        "first_bytes_ascii": _safe_ascii(first_bytes),
        "first_bytes_text": first_bytes.decode("utf-8", errors="ignore") if first_bytes else "",
        "tunnel_hints": tunnel_hints[:20],
    }


def register(app: FastAPI):
    @app.post("/api/session/{sid}/analyze/icmp")
    def api_analyze(sid: str):
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        return analyze(sess)
