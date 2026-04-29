"""PcapPal FastAPI backend."""
import os
import re
import shutil
import tempfile
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from backend.session import create_session, get_session, store_packets, rebuild_indexes
from backend.parser import parse_pcap
from backend.utils import safe_ascii

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

app = FastAPI(title="PcapPal", version="2.0")

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def root():
    return FileResponse("static/index.html")


# ============== Upload ==============
@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1].lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {suffix}. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
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
        p["ascii"] = safe_ascii(raw)
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
    src = ip.get("src")
    dst = ip.get("dst")
    sport = tcp.get("sport")
    dport = tcp.get("dport")
    if not all([src, dst, sport is not None, dport is not None]):
        return ""
    a = f"{src}:{sport}"
    b = f"{dst}:{dport}"
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

_HTTP_START_RE = re.compile(br"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|HTTP/)")


def _find_next_http_start(data: bytes) -> int:
    m = _HTTP_START_RE.search(data)
    return m.start() if m else -1


def _header_get(headers: dict, name: str, default: str = "") -> str:
    """Case-insensitive header lookup."""
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return default


def _decode_chunked(data: bytes) -> tuple:
    """Decode HTTP chunked transfer-encoding body.
    Returns (decoded_body, consumed_bytes) where consumed_bytes includes
    the terminating 0\\r\\n\\r\\n trailer."""
    result = bytearray()
    offset = 0
    while offset < len(data):
        # Find chunk size line
        crlf = data.find(b"\r\n", offset)
        if crlf < 0:
            break
        size_str = data[offset:crlf].decode("ascii", errors="ignore").split(";")[0].strip()
        try:
            chunk_size = int(size_str, 16)
        except ValueError:
            break
        if chunk_size == 0:
            # Terminal chunk — skip 0\r\n and any trailers until \r\n
            end_of_trailer = data.find(b"\r\n", crlf + 2)
            if end_of_trailer >= 0:
                offset = end_of_trailer + 2
            else:
                offset = len(data)
            break
        chunk_start = crlf + 2
        chunk_end = chunk_start + chunk_size
        if chunk_end > len(data):
            result.extend(data[chunk_start:])
            offset = len(data)
            break
        result.extend(data[chunk_start:chunk_end])
        # Skip trailing CRLF after chunk data
        offset = chunk_end + 2
    return bytes(result), offset


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
    leading_nulls = len(data) - len(stripped)

    # If stripping nulls corrupted the start line (e.g. \x00\x00HTTP -> TTP),
    # look for the HTTP start directly in the raw data and realign
    if stripped and not stripped.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ",
                                             b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
                                             b"TRACE ", b"HTTP/")):
        m = _HTTP_START_RE.search(stripped)
        if m and m.start() > 0:
            # The null bytes consumed part of the actual HTTP start line.
            # Recalculate: the real start was at leading_nulls - m.start()
            # but simpler: just skip the garbage in stripped
            leading_nulls += m.start()
            stripped = stripped[m.start():]

    # Find header end in raw bytes (no size limit — headers can be very large)
    sep_idx = stripped.find(b"\r\n\r\n")
    if sep_idx >= 0:
        header_end_bytes = sep_idx + 4  # past the \r\n\r\n
    else:
        sep_idx = stripped.find(b"\n\n")
        if sep_idx >= 0:
            header_end_bytes = sep_idx + 2
        else:
            header_end_bytes = -1

    if header_end_bytes == -1:
        return None

    # Decode only the header portion for parsing
    header_raw = stripped[:sep_idx]
    text = header_raw.decode("utf-8", errors="ignore")
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

    # Parse headers
    headers = {}
    for line in lines[1:]:
        if line == "":
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    # header_end relative to original data (includes leading nulls)
    header_end = header_end_bytes + leading_nulls

    body = data[header_end:]
    is_chunked = _header_get(headers, "Transfer-Encoding", "").lower() == "chunked"

    if is_req:
        if is_chunked:
            actual_body, chunk_consumed = _decode_chunked(body)
            consumed = chunk_consumed
        else:
            cl = _header_get(headers, "Content-Length")
            if cl and cl.isdigit():
                body_len = min(int(cl), len(body))
            else:
                if method in ("GET", "HEAD", "DELETE", "OPTIONS", "TRACE", "CONNECT"):
                    body_len = 0
                else:
                    body_len = len(body)
            actual_body = body[:body_len]
            consumed = body_len
        return {
            "isRequest": True,
            "method": method,
            "uri": uri,
            "version": version,
            "headers": headers,
            "body_hex": actual_body.hex(),
            "body_ascii": safe_ascii(actual_body),
            "_consumed": header_end + consumed,
            "chunked": is_chunked,
        }
    else:
        # No body for 1xx, 204 No Content, 304 Not Modified
        if status in (100, 101, 204, 304):
            body_len = 0
            actual_body = b""
            consumed = 0
        elif is_chunked:
            actual_body, chunk_consumed = _decode_chunked(body)
            consumed = chunk_consumed
        else:
            cl = _header_get(headers, "Content-Length")
            if cl and cl.isdigit():
                body_len = min(int(cl), len(body))
            else:
                # No Content-Length: look for next HTTP message to limit body
                next_start = _find_next_http_start(body)
                if next_start > 0:
                    body_len = next_start
                else:
                    body_len = len(body)
            actual_body = body[:body_len]
            consumed = body_len
        return {
            "isRequest": False,
            "status": status,
            "statusText": status_text,
            "version": version,
            "headers": headers,
            "body_hex": actual_body.hex(),
            "body_ascii": safe_ascii(actual_body),
            "_consumed": header_end + consumed,
            "chunked": is_chunked,
        }


def _is_spurious_payload(tcph: dict, payload: bytes) -> bool:
    """Filter out bogus TCP payloads that Scapy mis-parses from options/padding."""
    if not payload:
        return True
    flags = tcph.get("flags", "")
    # SYN / SYN+ACK packets never carry application data
    if "S" in flags and "A" not in flags:  # SYN only
        return True
    # Pure-null payloads <= 6 bytes are almost always TCP option padding
    if len(payload) <= 6 and payload == b"\x00" * len(payload):
        return True
    # SYN+ACK with any payload — the payload is always bogus
    if "S" in flags and "A" in flags:
        return True
    return False


def _reassemble_direction(dpackets: List[Dict]) -> bytes:
    """Reassemble one direction of a TCP stream, handling retransmissions
    and filtering spurious payloads."""
    has_seq = all(
        p.get("layers", {}).get("tcp", {}).get("seq") is not None
        for p in dpackets
    )
    if has_seq:
        # Build seq -> (payload, pkt_index) keeping the longest payload per seq
        seq_segments: Dict[int, tuple] = {}
        for p in dpackets:
            tcph = p.get("layers", {}).get("tcp", {})
            payload_hex = tcph.get("payload_hex", "")
            payload = bytes.fromhex(payload_hex) if payload_hex else b""
            if _is_spurious_payload(tcph, payload):
                continue
            seq = tcph.get("seq", 0)
            if seq not in seq_segments or len(payload) > len(seq_segments[seq][0]):
                seq_segments[seq] = (payload, p["index"])

        # Reassemble in seq order, skipping bytes already covered
        sorted_seqs = sorted(seq_segments.keys())
        reassembled = bytearray()
        covered_end: Optional[int] = None
        for seq in sorted_seqs:
            payload = seq_segments[seq][0]
            if covered_end is None:
                reassembled.extend(payload)
                covered_end = seq + len(payload)
            elif seq >= covered_end:
                reassembled.extend(payload)
                covered_end = seq + len(payload)
            elif seq + len(payload) > covered_end:
                overlap = covered_end - seq
                if overlap < len(payload):
                    reassembled.extend(payload[overlap:])
                    covered_end = seq + len(payload)
        return bytes(reassembled)
    else:
        dpackets.sort(key=lambda p: p["timestamp"])
        parts = []
        for p in dpackets:
            tcph = p.get("layers", {}).get("tcp", {})
            payload_hex = tcph.get("payload_hex", "")
            payload = bytes.fromhex(payload_hex) if payload_hex else b""
            if _is_spurious_payload(tcph, payload):
                continue
            parts.append(payload)
        return b"".join(parts)


def _get_http_transactions_cached(sess: dict) -> list:
    """Compute and cache HTTP transactions for a session."""
    if "http_transactions" in sess:
        return sess["http_transactions"]

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
        a_src = ip.get("src")
        a_dst = ip.get("dst")
        a_sport = tcp.get("sport")
        a_dport = tcp.get("dport")
        if not all([a_src, a_dst, a_sport is not None, a_dport is not None]):
            continue
        a = f"{a_src}:{a_sport}"
        b = f"{a_dst}:{a_dport}"
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
            d = f"{ip.get('src','')}:{tcp.get('sport',0)}->{ip.get('dst','')}:{tcp.get('dport',0)}"
            if d not in dirs:
                dirs[d] = []
            dirs[d].append(p)

        # Reassemble each direction and parse HTTP
        all_messages: List[Dict] = []
        for d, dpackets in dirs.items():
            # Find the first packet with real payload for accurate timestamp
            first_payload_pkt = None
            for p in dpackets:
                tcph = p.get("layers", {}).get("tcp", {})
                payload_hex = tcph.get("payload_hex", "")
                payload = bytes.fromhex(payload_hex) if payload_hex else b""
                if not _is_spurious_payload(tcph, payload) and len(payload) > 0:
                    first_payload_pkt = p
                    break
            if first_payload_pkt is None:
                # No real payload in this direction
                continue

            # Get src/dst from the first payload packet (correct direction)
            iph = first_payload_pkt.get("layers", {}).get("ip", {})
            tcph = first_payload_pkt.get("layers", {}).get("tcp", {})

            data = _reassemble_direction(dpackets)
            if not data:
                continue

            msgs = _parse_http_messages(data)
            for msg in msgs:
                msg["_direction"] = d
                msg["_streamKey"] = key
                msg["_packetIndices"] = [p["index"] for p in dpackets]
                msg["_timestamp"] = first_payload_pkt["timestamp"]
                msg["_src"] = iph.get("src", "")
                msg["_dst"] = iph.get("dst", "")
                msg["_sport"] = tcph.get("sport", 0)
                msg["_dport"] = tcph.get("dport", 0)
                all_messages.append(msg)

        # Sort all messages by timestamp for correct temporal ordering
        all_messages.sort(key=lambda m: m.get("_timestamp", 0))

        # Separate requests and responses
        reqs = [m for m in all_messages if m.get("isRequest")]
        resps = [m for m in all_messages if not m.get("isRequest")]

        # Pair requests and responses using timestamp proximity.
        # For each request, find the closest response within a generous window.
        # Allow responses to be slightly before the request (SYN+ACK arrives
        # before the request payload is fully sent).
        used_resps = set()
        for req in reqs:
            req_ts = req.get("_timestamp", 0)
            best_resp = None
            best_idx = -1
            best_dt = float("inf")
            for j, resp in enumerate(resps):
                if j in used_resps:
                    continue
                dt = abs(resp.get("_timestamp", 0) - req_ts)
                if dt < best_dt:
                    best_dt = dt
                    best_resp = resp
                    best_idx = j
            if best_resp is not None and best_dt < 30:  # within 30 seconds
                used_resps.add(best_idx)
            else:
                best_resp = None
            transactions.append(_finalize_tx_from_msg(tx_id, req, best_resp))
            tx_id += 1

        # Add unmatched responses
        for j, resp in enumerate(resps):
            if j not in used_resps:
                transactions.append(_finalize_tx_from_msg(tx_id, None, resp))
                tx_id += 1

    sess["http_transactions"] = transactions
    return transactions


@app.get("/api/session/{sid}/http")
def get_http_transactions(sid: str):
    sess = get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    return _get_http_transactions_cached(sess)


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
        tx["host"] = _header_get(req_msg.get("headers", {}), "Host")
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


@app.post("/api/session/{sid}/sslkeylog")
async def upload_sslkeylog(sid: str, file: UploadFile = File(...)):
    """Upload SSLKEYLOGFILE and decrypt TLS traffic using tshark."""
    sess = get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    if sess.get("decrypted"):
        raise HTTPException(status_code=400, detail="Session already decrypted. Re-upload the original pcap to decrypt with a different key.")

    # Check if tshark is available
    if not shutil.which("tshark"):
        raise HTTPException(status_code=500, detail="tshark not found. Please install Wireshark/tshark.")

    # Save keylog file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="wb") as tmp:
        content = await file.read()
        tmp.write(content)
        keylog_path = tmp.name

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
        rebuild_indexes(sess)
        sess["decrypted"] = True
        sess["sslkeylog"] = True
        # Invalidate cached HTTP transactions
        sess.pop("http_transactions", None)
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
