"""SQL injection traffic detector."""
import re
from fastapi import FastAPI, HTTPException
from backend.session import get_session

SQL_PATTERNS = [
    re.compile(r"union\s+select", re.I),
    re.compile(r"sleep\s*\(\s*\d+", re.I),
    re.compile(r"benchmark\s*\(", re.I),
    re.compile(r"information_schema", re.I),
    re.compile(r"select\s+.{0,30}from", re.I),
    re.compile(r"and\s+\d+\s*=\s*\d+", re.I),
    re.compile(r"or\s+'\d+'\s*=\s*'\d+'", re.I),
    re.compile(r"substr\s*\(\s*.+?,\s*\d+\s*,\s*\d+\s*\)", re.I),
    re.compile(r"mid\s*\(\s*.+?,\s*\d+\s*,\s*\d+\s*\)", re.I),
    re.compile(r"ascii\s*\(\s*substr", re.I),
    re.compile(r"if\s*\(\s*\d+\s*=\s*\d+\s*,\s*sleep", re.I),
    re.compile(r"(and|or)\s+\d+\s*>=\s*\d+", re.I),
]


def analyze(session: dict) -> dict:
    packets = session["packets"]
    matches = []

    for p in packets:
        text = ""
        if p.get("protocol") == "HTTP":
            http = p.get("layers", {}).get("http", {})
            text = http.get("uri", "") + " " + http.get("body_ascii", "")
        else:
            tcp = p.get("layers", {}).get("tcp", {})
            if tcp:
                text = tcp.get("payload_ascii", "")

        if not text:
            continue

        found = []
        for pat in SQL_PATTERNS:
            for m in pat.finditer(text):
                found.append(m.group(0))
        if found:
            matches.append({
                "index": p["index"],
                "proto": p.get("protocol", ""),
                "matches": list(set(found)),
                "preview": text[:300],
            })

    return {
        "count": len(matches),
        "matches": matches[:100],
    }


def register(app: FastAPI):
    @app.post("/api/session/{sid}/analyze/sql")
    def api_analyze(sid: str):
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        return analyze(sess)
