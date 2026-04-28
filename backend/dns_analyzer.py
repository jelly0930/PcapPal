"""DNS tunneling and query analyzer."""
import base64
import re
from typing import Dict, List
from fastapi import FastAPI, HTTPException
from backend.session import get_session
from backend.parser import DNS_TYPE_NAMES


def _decode_base32_subdomain(name: str) -> str:
    """Try to decode a subdomain as base32."""
    # Remove non-base32 chars and pad
    clean = "".join(c for c in name if c.lower() in "abcdefghijklmnopqrstuvwxyz234567")
    if len(clean) < 4:
        return ""
    try:
        # Pad to multiple of 8
        padded = clean + ("=" * (8 - len(clean) % 8) if len(clean) % 8 else "")
        decoded = base64.b32decode(padded.upper())
        text = decoded.decode("utf-8", errors="ignore")
        # Only return if mostly printable
        if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text):
            return text
    except Exception:
        pass
    return ""


def _extract_txt_data(data: str) -> str:
    """Extract string data from DNS TXT record (already decoded by parser)."""
    return data if data else ""


def analyze(session: dict) -> dict:
    packets = session["packets"]
    queries = []
    answers = []
    suspicious = []
    txt_records = []
    domain_stats: Dict[str, int] = {}
    subdomain_lengths = []

    for p in packets:
        if p.get("protocol") == "DNS":
            dns = p.get("layers", {}).get("dns", {})
            for q in dns.get("queries", []):
                name = q.get("name", "").rstrip(".")
                qtype = q.get("type")
                qtype_str = DNS_TYPE_NAMES.get(qtype, f"TYPE{qtype}") if qtype else "?"
                queries.append({"index": p["index"], "name": name, "type": qtype, "typeStr": qtype_str})
                # Domain stats
                domain_stats[name] = domain_stats.get(name, 0) + 1
                # Heuristic: long subdomain names may be DNS tunneling
                parts = name.split(".")
                if len(name) > 50 or name.count(".") > 5:
                    suspicious.append({
                        "index": p["index"], "name": name,
                        "reason": "long subdomain / tunneling-like",
                        "length": len(name),
                    })
                # Subdomain length analysis (for length-based steganography)
                if len(parts) > 2:
                    for sub in parts[:-2]:
                        if sub:
                            subdomain_lengths.append({"index": p["index"], "sub": sub, "len": len(sub)})

            for a in dns.get("answers", []):
                name = a.get("name", "").rstrip(".")
                atype = a.get("type")
                atype_str = DNS_TYPE_NAMES.get(atype, f"TYPE{atype}") if atype else "?"
                data = a.get("data", "")
                # Try to extract meaningful TXT data
                txt_data = ""
                if atype == 16 and data:
                    txt_data = _extract_txt_data(data)
                    txt_records.append({
                        "index": p["index"], "name": name, "data": txt_data,
                        "raw": str(data),
                    })
                answers.append({
                    "index": p["index"], "name": name,
                    "type": atype, "typeStr": atype_str, "data": data,
                    "txtData": txt_data,
                })

    # Try base32 decode on suspicious long subdomains
    base32_decoded = []
    for s in suspicious:
        decoded = _decode_base32_subdomain(s["name"])
        if decoded:
            base32_decoded.append({"name": s["name"], "decoded": decoded})

    # Top domains
    top_domains = sorted(domain_stats.items(), key=lambda x: -x[1])[:30]

    # Check if subdomain lengths encode ASCII
    length_ascii = ""
    if subdomain_lengths:
        for item in subdomain_lengths:
            l = item["len"]
            if 32 <= l < 127:
                length_ascii += chr(l)

    return {
        "queryCount": len(queries),
        "answerCount": len(answers),
        "queries": queries[:200],
        "answers": answers[:200],
        "suspicious": suspicious[:50],
        "txtRecords": txt_records[:100],
        "topDomains": top_domains,
        "base32Decoded": base32_decoded[:20],
        "subdomainLengthAscii": length_ascii[:500],
    }


def register(app: FastAPI):
    @app.post("/api/session/{sid}/analyze/dns")
    def api_analyze(sid: str):
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        return analyze(sess)
