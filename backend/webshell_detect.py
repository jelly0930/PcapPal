"""Webshell traffic detector (China Chopper, AntSword, Behinder, Godzilla features)."""
import re
import base64
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException
from backend.session import get_session

WEBSHELL_SIGNATURES = {
    "china_chopper": re.compile(r"(eval|assert)\s*\(\s*[@$]\w+", re.I),
    "antsword": re.compile(r"(assert|eval|execute)\s*\(\s*[@$]\w+|cmd=|antSword", re.I),
    "behinder": re.compile(r"(\.php|\.jsp|\.aspx)\?pass=|behinder|冰蝎", re.I),
    "godzilla": re.compile(r"(godzilla|哥斯拉|gz|pass=\w{16,32})", re.I),
}


def analyze(session: dict) -> dict:
    packets = session["packets"]
    matches = []

    for p in packets:
        if p.get("protocol") != "HTTP":
            continue
        http = p.get("layers", {}).get("http", {})
        body_ascii = http.get("body_ascii", "")
        body_hex = http.get("body_hex", "")
        uri = http.get("uri", "")
        headers = http.get("headers", {})

        # Check User-Agent for webshell tools
        ua = headers.get("User-Agent", "")
        signs = []
        for name, pat in WEBSHELL_SIGNATURES.items():
            if pat.search(body_ascii) or pat.search(uri) or pat.search(ua):
                signs.append(name)

        # Heuristic: base64-heavy body
        b64_like = re.findall(r"[A-Za-z0-9+/]{100,}=?=]?", body_ascii)
        if len(b64_like) > 2:
            signs.append("heavy_base64")

        if signs:
            matches.append({
                "index": p["index"],
                "uri": uri,
                "method": http.get("method", ""),
                "signatures": list(set(signs)),
                "body_preview": body_ascii[:300],
                "ua": ua,
            })

    return {
        "count": len(matches),
        "matches": matches[:100],
    }


def register(app: FastAPI):
    @app.post("/api/session/{sid}/analyze/webshell")
    def api_analyze(sid: str):
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        return analyze(sess)
