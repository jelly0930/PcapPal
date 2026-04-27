"""FTP and Telnet analyzer: extract credentials and commands."""
import re
from fastapi import FastAPI, HTTPException
from backend.session import get_session


def analyze(session: dict) -> dict:
    packets = session["packets"]
    ftp_cmds = []
    ftp_files = []
    telnet_texts = []
    creds = []

    for p in packets:
        proto = p.get("protocol", "")
        tcp = p.get("layers", {}).get("tcp", {})
        payload_ascii = tcp.get("payload_ascii", "") if tcp else ""
        if not payload_ascii:
            continue

        # FTP on port 21
        if p.get("srcPort") == 21 or p.get("dstPort") == 21:
            # Use raw payload from hex to preserve newlines
            raw_payload = bytes.fromhex(tcp.get("payload_hex", "")) if tcp.get("payload_hex") else b""
            text = raw_payload.decode("utf-8", errors="ignore")
            lines = text.splitlines()
            for line in lines:
                line = line.strip()
                if line:
                    ftp_cmds.append({"index": p["index"], "line": line, "direction": "server" if p.get("srcPort") == 21 else "client"})
                # Detect login
                m = re.match(r"(?i)USER\s+(\S+)", line)
                if m:
                    creds.append({"index": p["index"], "proto": "FTP", "user": m.group(1)})
                m = re.match(r"(?i)PASS\s+(\S+)", line)
                if m:
                    creds.append({"index": p["index"], "proto": "FTP", "pass": m.group(1)})
                m = re.match(r"(?i)RETR\s+(\S+)", line)
                if m:
                    ftp_files.append({"index": p["index"], "file": m.group(1), "action": "download"})
                m = re.match(r"(?i)STOR\s+(\S+)", line)
                if m:
                    ftp_files.append({"index": p["index"], "file": m.group(1), "action": "upload"})

        # Telnet on port 23
        if p.get("srcPort") == 23 or p.get("dstPort") == 23:
            raw_payload = bytes.fromhex(tcp.get("payload_hex", "")) if tcp.get("payload_hex") else b""
            text = raw_payload.decode("utf-8", errors="ignore")
            # Strip telnet control sequences
            cleaned = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
            cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", cleaned)
            if cleaned.strip():
                telnet_texts.append({"index": p["index"], "text": cleaned.strip()})

    return {
        "ftp_commands": ftp_cmds[:200],
        "ftp_transfers": ftp_files[:50],
        "telnet_sessions": telnet_texts[:200],
        "credentials": creds[:50],
    }


def register(app: FastAPI):
    @app.post("/api/session/{sid}/analyze/ftp")
    def api_analyze(sid: str):
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        return analyze(sess)
