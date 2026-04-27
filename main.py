"""PcapPal FastAPI backend."""
import os
import tempfile
import time
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from backend.session import create_session, get_session, store_packets
from backend.parser import parse_pcap

app = FastAPI(title="PcapPal", version="2.0")

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def root():
    return FileResponse("static/index.html")


# ============== Upload ==============
@app.post("/api/upload")
def upload_file(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file.file.read())
        tmp_path = tmp.name

    sid = create_session()
    try:
        packets = parse_pcap(tmp_path)
    except Exception as e:
        os.unlink(tmp_path)
        raise HTTPException(status_code=400, detail=f"Parse error: {e}")

    # Keep original pcap for possible TLS decryption later
    store_packets(sid, packets, file.filename or "", original_path=tmp_path)
    sess = get_session(sid)
    return {
        "session_id": sid,
        "count": len(packets),
        "filename": file.filename,
        "firstTimestamp": sess.get("first_timestamp", 0.0) if sess else 0.0,
    }


# ============== Packets ==============
class PacketSummary(BaseModel):
    index: int
    timestamp: float
    length: int
    protocol: str
    src: str
    dst: str
    srcPort: Optional[int]
    dstPort: Optional[int]
    info: str


@app.get("/api/session/{sid}/packets")
def get_packets(
    sid: str,
    page: int = Query(1, ge=1),
    size: int = Query(100, ge=10, le=1000),
    filter: str = Query(""),
    sort: str = Query(""),
    sort_dir: str = Query("asc"),
):
    sess = get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    all_packets = sess["packets"]
    packets = all_packets
    if filter:
        f = filter.lower()
        packets = [
            p for p in packets
            if f in str(p.get("index", "")).lower()
            or f in str(p.get("src", "")).lower()
            or f in str(p.get("dst", "")).lower()
            or f in str(p.get("srcPort", "") or "").lower()
            or f in str(p.get("dstPort", "") or "").lower()
            or f in str(p.get("protocol", "")).lower()
            or f in str(p.get("info", "")).lower()
        ]

    total = len(packets)
    total_unfiltered = len(all_packets)

    # Sorting
    valid_sorts = {"index", "timestamp", "length", "protocol", "src", "dst", "srcPort", "dstPort", "info"}
    if sort in valid_sorts:
        reverse = sort_dir.lower() == "desc"
        def _sort_key(p):
            val = p.get(sort)
            if val is None:
                return (1, "")
            return (0, val)
        packets = sorted(packets, key=_sort_key, reverse=reverse)

    start = (page - 1) * size
    end = start + size
    page_data = packets[start:end]

    # Strip internal/private fields (e.g. _raw bytes) before JSON serialization
    def _clean(pkt: dict) -> dict:
        return {k: v for k, v in pkt.items() if not k.startswith("_")}

    return {
        "total": total,
        "totalUnfiltered": total_unfiltered,
        "page": page,
        "size": size,
        "data": [_clean(p) for p in page_data],
    }


def _ensure_hex_ascii(p: dict) -> dict:
    """Lazy-generate hex/ascii for a packet if not already present."""
    if "hex" not in p:
        raw = p.pop("_raw", b"")
        p["hex"] = raw.hex() if raw else ""
        p["ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
    # Strip internal fields before returning to client
    p.pop("_raw", None)
    return p


@app.get("/api/session/{sid}/packet/{idx}")
def get_packet_detail(sid: str, idx: int):
    sess = get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    p = sess.get("packet_by_index", {}).get(idx)
    if not p:
        raise HTTPException(status_code=404, detail="Packet not found")
    return _ensure_hex_ascii(p.copy())


# ============== Streams ==============
def _stream_key(pkt: dict) -> str:
    ip = pkt.get("layers", {}).get("ip", {})
    tcp = pkt.get("layers", {}).get("tcp", {})
    if not ip or not tcp:
        return ""
    a = f"{ip['src']}:{tcp['sport']}"
    b = f"{ip['dst']}:{tcp['dport']}"
    return f"{min(a,b)} <-> {max(a,b)}"


@app.get("/api/session/{sid}/streams")
def get_streams(sid: str):
    sess = get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    streams: Dict[str, Dict[str, Any]] = {}
    for p in sess["packets"]:
        tcp = p.get("layers", {}).get("tcp", {})
        if not tcp:
            continue
        payload_hex = tcp.get("payload_hex", "")
        if not payload_hex:
            continue
        key = _stream_key(p)
        if not key:
            continue
        if key not in streams:
            ip = p.get("layers", {}).get("ip", {})
            streams[key] = {
                "key": key,
                "src": ip.get("src", ""),
                "sport": tcp.get("sport", 0),
                "dst": ip.get("dst", ""),
                "dport": tcp.get("dport", 0),
                "packets": 0,
                "bytes": 0,
            }
        streams[key]["packets"] += 1
        streams[key]["bytes"] += len(payload_hex) // 2

    return list(streams.values())


@app.get("/api/session/{sid}/stream/{key}")
def get_stream_content(sid: str, key: str):
    sess = get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    segs = []
    for p in sess["packets"]:
        if _stream_key(p) == key:
            tcp = p.get("layers", {}).get("tcp", {})
            if tcp and tcp.get("payload_hex"):
                segs.append({
                    "index": p["index"],
                    "src": p.get("src", ""),
                    "sport": p.get("srcPort"),
                    "dst": p.get("dst", ""),
                    "dport": p.get("dstPort"),
                    "flags": tcp.get("flags", ""),
                    "seq": tcp.get("seq", 0),
                    "hex": tcp["payload_hex"],
                    "ascii": tcp.get("payload_ascii", ""),
                })
    return {"key": key, "segments": segs}


# ============== HTTP ==============

def _safe_ascii(data: bytes) -> str:
    if not data:
        return ""
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data)


import re
_HTTP_START_RE = re.compile(br"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|HTTP/)")


def _find_next_http_start(data: bytes) -> int:
    m = _HTTP_START_RE.search(data)
    return m.start() if m else -1


def _parse_http_messages(data: bytes) -> List[Dict[str, Any]]:
    """Parse all HTTP request/response messages from reassembled TCP data."""
    messages = []
    offset = 0
    while offset < len(data):
        msg = _parse_single_http(data[offset:])
        if msg:
            messages.append(msg)
            consumed = msg.get("_consumed", len(data) - offset)
            offset += consumed
            continue
        # Skip garbage (null bytes, padding, etc.) and try again
        next_start = _find_next_http_start(data[offset:])
        if next_start > 0:
            offset += next_start
        else:
            break
    return messages


def _parse_single_http(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 16:
        return None
    # Strip leading nulls/spaces so HTTP start line is at position 0
    stripped = data.lstrip(b"\x00")
    text = stripped[:2048].decode("utf-8", errors="ignore")
    lines = text.split("\r\n")
    if len(lines) < 2:
        lines = text.split("\n")
    if not lines:
        return None

    first = lines[0]
    is_req = False
    is_resp = False

    if first.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ")):
        parts = first.split(" ")
        if len(parts) >= 3 and parts[2].startswith("HTTP/"):
            is_req = True
            method = parts[0]
            uri = parts[1]
            version = parts[2].split("/")[1]
    elif first.startswith("HTTP/"):
        parts = first.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
                is_resp = True
                version = parts[0].split("/")[1]
                status_text = parts[2] if len(parts) > 2 else ""
            except ValueError:
                pass

    if not is_req and not is_resp:
        return None

    # Find header end in stripped data
    header_end = -1
    for i in range(len(text) - 3):
        if text[i:i+4] == "\r\n\r\n":
            header_end = i + 4
            break
        elif text[i:i+2] == "\n\n" and header_end == -1:
            header_end = i + 2

    if header_end == -1:
        return None

    # Adjust header_end to be relative to original data
    leading_nulls = len(data) - len(stripped)
    header_end += leading_nulls

    # Parse headers
    headers = {}
    header_text = text[:header_end - leading_nulls]
    for line in header_text.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    body = data[header_end:]

    if is_req:
        cl = headers.get("Content-Length", "")
        if cl and cl.isdigit():
            body_len = min(int(cl), len(body))
        else:
            # Methods that typically have no body unless Content-Length is present
            if method in ("GET", "HEAD", "DELETE", "OPTIONS", "TRACE", "CONNECT"):
                body_len = 0
            else:
                body_len = len(body)
        actual_body = body[:body_len]
        return {
            "isRequest": True,
            "method": method,
            "uri": uri,
            "version": version,
            "headers": headers,
            "body_hex": actual_body.hex(),
            "body_ascii": _safe_ascii(actual_body),
            "_consumed": header_end + body_len,
        }
    else:
        # No body for 1xx, 204 No Content, 304 Not Modified
        if status in (100, 101, 204, 304):
            body_len = 0
        else:
            cl = headers.get("Content-Length", "")
            if cl and cl.isdigit():
                body_len = min(int(cl), len(body))
            else:
                body_len = len(body)
        actual_body = body[:body_len]
        return {
            "isRequest": False,
            "status": status,
            "statusText": status_text,
            "version": version,
            "headers": headers,
            "body_hex": actual_body.hex(),
            "body_ascii": _safe_ascii(actual_body),
            "_consumed": header_end + body_len,
        }


@app.get("/api/session/{sid}/http")
def get_http_transactions(sid: str):
    sess = get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    packets = sess["packets"]

    # Group all TCP packets by bidirectional stream key
    streams: Dict[str, List[Dict[str, Any]]] = {}
    for p in packets:
        tcp = p.get("layers", {}).get("tcp", {})
        if not tcp or not tcp.get("payload_hex"):
            continue
        ip = p.get("layers", {}).get("ip", {})
        if not ip:
            continue
        a = f"{ip['src']}:{tcp['sport']}"
        b = f"{ip['dst']}:{tcp['dport']}"
        key = f"{min(a,b)} <-> {max(a,b)}"
        if key not in streams:
            streams[key] = []
        streams[key].append(p)

    transactions = []
    tx_id = 1

    for key, stream_packets in streams.items():
        # Group by direction
        dirs: Dict[str, List[Dict]] = {}
        for p in stream_packets:
            tcp = p.get("layers", {}).get("tcp", {})
            ip = p.get("layers", {}).get("ip", {})
            d = f"{ip['src']}:{tcp['sport']}->{ip['dst']}:{tcp['dport']}"
            if d not in dirs:
                dirs[d] = []
            dirs[d].append(p)

        # Reassemble each direction and parse HTTP
        all_messages: List[Dict] = []
        for d, dpackets in dirs.items():
            has_seq = all(
                p.get("layers", {}).get("tcp", {}).get("seq") is not None
                for p in dpackets
            )
            if has_seq:
                dpackets.sort(key=lambda p: p.get("layers", {}).get("tcp", {}).get("seq", 0))
            else:
                dpackets.sort(key=lambda p: p["timestamp"])

            data = b"".join(
                bytes.fromhex(p.get("layers", {}).get("tcp", {}).get("payload_hex", ""))
                for p in dpackets
            )
            if not data:
                continue

            first_pkt = dpackets[0]
            tcp = first_pkt.get("layers", {}).get("tcp", {})
            ip = first_pkt.get("layers", {}).get("ip", {})

            msgs = _parse_http_messages(data)
            for msg in msgs:
                msg["_direction"] = d
                msg["_streamKey"] = key
                msg["_packetIndices"] = [p["index"] for p in dpackets]
                msg["_timestamp"] = first_pkt["timestamp"]
                msg["_src"] = first_pkt.get("src", "")
                msg["_dst"] = first_pkt.get("dst", "")
                msg["_sport"] = tcp.get("sport", 0)
                msg["_dport"] = tcp.get("dport", 0)
                all_messages.append(msg)

        # Separate requests and responses
        reqs = [m for m in all_messages if m.get("isRequest")]
        resps = [m for m in all_messages if not m.get("isRequest")]

        # Pair by order within the stream (HTTP/1.1 without pipelining is strictly alternating)
        for i in range(max(len(reqs), len(resps))):
            req = reqs[i] if i < len(reqs) else None
            resp = resps[i] if i < len(resps) else None
            if req or resp:
                transactions.append(_finalize_tx_from_msg(tx_id, req, resp))
                tx_id += 1

    return transactions


def _finalize_tx_from_msg(tx_id: int, req_msg: Optional[Dict], resp_msg: Optional[Dict]) -> Dict[str, Any]:
    """Build a transaction dict from parsed HTTP message dicts."""
    tx: Dict[str, Any] = {"id": tx_id}

    if req_msg:
        tx["src"] = req_msg.get("_src", "")
        tx["dst"] = req_msg.get("_dst", "")
        tx["srcPort"] = req_msg.get("_sport", 0)
        tx["dstPort"] = req_msg.get("_dport", 0)
        tx["method"] = req_msg.get("method", "")
        tx["uri"] = req_msg.get("uri", "")
        tx["host"] = req_msg.get("headers", {}).get("Host", "")
        tx["requestHeaders"] = req_msg.get("headers", {})
        tx["requestBody"] = req_msg.get("body_ascii", "")[:65536]
        tx["requestBodyHex"] = req_msg.get("body_hex", "")
        tx["timestamp"] = req_msg.get("_timestamp", 0.0)
        tx["requestIndex"] = req_msg.get("_packetIndices", [None])[0]
    else:
        tx["src"] = resp_msg.get("_src", "") if resp_msg else ""
        tx["dst"] = resp_msg.get("_dst", "") if resp_msg else ""
        tx["srcPort"] = resp_msg.get("_sport", 0) if resp_msg else 0
        tx["dstPort"] = resp_msg.get("_dport", 0) if resp_msg else 0
        tx["method"] = ""
        tx["uri"] = ""
        tx["host"] = ""
        tx["requestHeaders"] = {}
        tx["requestBody"] = ""
        tx["requestBodyHex"] = ""
        tx["timestamp"] = resp_msg.get("_timestamp", 0.0) if resp_msg else 0.0
        tx["requestIndex"] = None

    if resp_msg:
        tx["status"] = resp_msg.get("status", 0)
        tx["statusText"] = resp_msg.get("statusText", "")
        tx["responseHeaders"] = resp_msg.get("headers", {})
        headers = resp_msg.get("headers", {})
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v
                break
        tx["contentType"] = ct
        tx["responseBody"] = resp_msg.get("body_ascii", "")[:65536]
        tx["responseBodyHex"] = resp_msg.get("body_hex", "")
        tx["responseBodyRaw"] = resp_msg.get("body_hex", "")
        tx["responseIndex"] = resp_msg.get("_packetIndices", [None])[0]
    else:
        tx["status"] = 0
        tx["statusText"] = ""
        tx["responseHeaders"] = {}
        tx["contentType"] = ""
        tx["responseBody"] = ""
        tx["responseBodyHex"] = ""
        tx["responseBodyRaw"] = ""
        tx["responseIndex"] = None

    indices = []
    if req_msg:
        indices.extend(req_msg.get("_packetIndices", []))
    if resp_msg:
        indices.extend(resp_msg.get("_packetIndices", []))
    tx["packetIndices"] = list(dict.fromkeys(indices))  # dedup while preserving order
    return tx


def _finalize_tx(tx_id: int, req_seg: Optional[Dict], resp_seg: Optional[Dict]) -> Dict[str, Any]:
    tx: Dict[str, Any] = {"id": tx_id}
    if req_seg:
        req = req_seg["http"]
        tx["src"] = req_seg["src"]
        tx["dst"] = req_seg["dst"]
        tx["srcPort"] = req_seg["srcPort"]
        tx["dstPort"] = req_seg["dstPort"]
        tx["method"] = req.get("method", "")
        tx["uri"] = req.get("uri", "")
        tx["host"] = req.get("headers", {}).get("Host", "")
        tx["requestHeaders"] = req.get("headers", {})
        tx["requestBody"] = req.get("body_ascii", "")[:2048]
        tx["requestBodyHex"] = req.get("body_hex", "")
        tx["timestamp"] = req_seg["timestamp"]
        tx["requestIndex"] = req_seg["index"]
    else:
        tx["src"] = resp_seg["src"] if resp_seg else ""
        tx["dst"] = resp_seg["dst"] if resp_seg else ""
        tx["srcPort"] = resp_seg["srcPort"] if resp_seg else 0
        tx["dstPort"] = resp_seg["dstPort"] if resp_seg else 0
        tx["method"] = ""
        tx["uri"] = ""
        tx["host"] = ""
        tx["requestHeaders"] = {}
        tx["requestBody"] = ""
        tx["requestBodyHex"] = ""
        tx["timestamp"] = resp_seg["timestamp"] if resp_seg else 0.0
        tx["requestIndex"] = None

    if resp_seg:
        resp = resp_seg["http"]
        tx["status"] = resp.get("status", 0)
        tx["statusText"] = resp.get("statusText", "")
        tx["responseHeaders"] = resp.get("headers", {})
        # Content-Type header case-insensitive lookup
        headers = resp.get("headers", {})
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v
                break
        tx["contentType"] = ct
        tx["responseBody"] = resp.get("body_ascii", "")[:2048]
        tx["responseBodyHex"] = resp.get("body_hex", "")
        tx["responseBodyRaw"] = resp.get("body_hex", "")
        tx["responseIndex"] = resp_seg["index"]
    else:
        tx["status"] = 0
        tx["statusText"] = ""
        tx["responseHeaders"] = {}
        tx["contentType"] = ""
        tx["responseBody"] = ""
        tx["responseBodyHex"] = ""
        tx["responseBodyRaw"] = ""
        tx["responseIndex"] = None

    # Collect all packet indices involved
    indices = []
    if req_seg:
        indices.append(req_seg["index"])
    if resp_seg:
        indices.append(resp_seg["index"])
    tx["packetIndices"] = indices
    return tx


# ============== Stats ==============
@app.get("/api/session/{sid}/stats")
def get_stats(sid: str):
    sess = get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    packets = sess["packets"]
    proto_counts = {}
    ip_counts = {}
    port_counts = {}
    total_len = 0
    for p in packets:
        proto = p.get("protocol", "UNKNOWN")
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
        if p.get("src"):
            ip_counts[p["src"]] = ip_counts.get(p["src"], 0) + 1
        if p.get("dst"):
            ip_counts[p["dst"]] = ip_counts.get(p["dst"], 0) + 1
        if p.get("srcPort"):
            port_counts[p["srcPort"]] = port_counts.get(p["srcPort"], 0) + 1
        if p.get("dstPort"):
            port_counts[p["dstPort"]] = port_counts.get(p["dstPort"], 0) + 1
        total_len += p.get("length", 0)

    return {
        "totalPackets": len(packets),
        "totalBytes": total_len,
        "protoCounts": proto_counts,
        "ipCounts": sorted(ip_counts.items(), key=lambda x: -x[1])[:50],
        "portCounts": sorted(port_counts.items(), key=lambda x: -x[1])[:50],
    }


# ============== Analyzer imports ==============
# Import and register analyzers
from backend import (
    flag_hunter, usb_analyzer, icmp_analyzer,
    dns_analyzer, file_extractor, ftp_telnet,
    webshell_detect, sql_inject, portscan, arp_analyzer,
    webshell_decryptor
)

# Register routes via helper
_analyzers = [
    ("flag", flag_hunter),
    ("usb", usb_analyzer),
    ("icmp", icmp_analyzer),
    ("dns", dns_analyzer),
    ("files", file_extractor),
    ("ftp", ftp_telnet),
    ("webshell", webshell_detect),
    ("sql", sql_inject),
    ("portscan", portscan),
    ("arp", arp_analyzer),
]

for _name, _mod in _analyzers:
    if hasattr(_mod, "register"):
        _mod.register(app)

# Register webshell decryptor routes
if hasattr(webshell_decryptor, "register"):
    webshell_decryptor.register(app)


# ============== TLS Decryption ==============
import subprocess
import tempfile
import shutil


@app.post("/api/session/{sid}/sslkeylog")
async def upload_sslkeylog(sid: str, file: UploadFile = File(...)):
    """Upload SSLKEYLOGFILE and decrypt TLS traffic using tshark."""
    sess = get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    # Check if tshark is available
    if not shutil.which("tshark"):
        raise HTTPException(status_code=500, detail="tshark not found. Please install Wireshark/tshark.")

    # Save keylog file
    suffix = ".txt"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode="wb") as tmp:
        content = await file.read()
        tmp.write(content)
        keylog_path = tmp.name

    # We need to re-read the original pcap to decrypt it.
    # Since we don't keep the original pcap after upload, we have two options:
    # 1. Reconstruct pcap from parsed packets (lossy)
    # 2. Keep original pcap in session
    # Let's add original_pcap_path to session storage.
    # For now, we check if session has original path stored.
    original_path = sess.get("original_path")
    if not original_path or not os.path.exists(original_path):
        os.unlink(keylog_path)
        raise HTTPException(status_code=400, detail="Original pcap not available for decryption. Please re-upload the file.")

    # Run tshark to decrypt
    decrypted_path = original_path + ".decrypted.pcap"
    try:
        cmd = [
            "tshark", "-o", f"ssl.keylog_file:{keylog_path}",
            "-r", original_path,
            "-w", decrypted_path,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            os.unlink(keylog_path)
            if os.path.exists(decrypted_path):
                os.unlink(decrypted_path)
            raise HTTPException(status_code=500, detail=f"tshark decryption failed: {proc.stderr}")
    except subprocess.TimeoutExpired:
        os.unlink(keylog_path)
        if os.path.exists(decrypted_path):
            os.unlink(decrypted_path)
        raise HTTPException(status_code=500, detail="tshark decryption timed out")

    # Parse decrypted pcap
    try:
        new_packets = parse_pcap(decrypted_path)
        for i, p in enumerate(new_packets):
            if i == 0:
                p["delta"] = 0.0
            else:
                p["delta"] = round(p["timestamp"] - new_packets[i - 1]["timestamp"], 6)
        sess["packets"] = new_packets
        sess["decrypted"] = True
        sess["sslkeylog"] = True
        # Cleanup
        os.unlink(keylog_path)
        os.unlink(decrypted_path)
        return {"success": True, "count": len(new_packets), "message": f"Decrypted {len(new_packets)} packets"}
    except Exception as e:
        os.unlink(keylog_path)
        if os.path.exists(decrypted_path):
            os.unlink(decrypted_path)
        raise HTTPException(status_code=500, detail=f"Parse decrypted pcap failed: {e}")


@app.get("/api/session/{sid}/tls-status")
def get_tls_status(sid: str):
    sess = get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "decrypted": sess.get("decrypted", False),
        "sslkeylog": sess.get("sslkeylog", False),
    }
