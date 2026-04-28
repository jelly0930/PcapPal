"""Extract files from various protocols."""
import re
import struct
from urllib.parse import unquote
from fastapi import FastAPI, HTTPException
from backend.session import get_session

# Extended file signatures for CTF scenarios
FILE_SIGNATURES = {
    # Archives
    "zip":     (b"\x50\x4b\x03\x04", ".zip"),
    "gzip":    (b"\x1f\x8b", ".gz"),
    "rar":     (b"Rar!", ".rar"),
    "tar":     (b"ustar", ".tar"),
    "7z":      (b"\x37\x7a\xbc\xaf\x27\x1c", ".7z"),
    "bz2":     (b"BZ", ".bz2"),
    "xz":      (b"\xfd\x37\x7a\x58\x5a\x00", ".xz"),
    # Images
    "png":     (b"\x89PNG\r\n\x1a\n", ".png"),
    "jpg":     (b"\xff\xd8\xff", ".jpg"),
    "gif":     (b"GIF89a", ".gif"),
    "gif87":   (b"GIF87a", ".gif"),
    "bmp":     (b"BM", ".bmp"),
    "webp":    (b"RIFF", ".webp"),  # needs further check
    "ico":     (b"\x00\x00\x01\x00", ".ico"),
    "tiff_be": (b"\x4d\x4d\x00\x2a", ".tiff"),
    "tiff_le": (b"\x49\x49\x2a\x00", ".tiff"),
    "psd":     (b"8BPS", ".psd"),
    # Documents
    "pdf":     (b"%PDF", ".pdf"),
    "elf":     (b"\x7fELF", ".elf"),
    # Office (ooxml / docx/xlsx/pptx)
    "ooxml":   (b"\x50\x4b\x03\x04", ".docx"),  # same as zip, distinguished later
    # Media
    "mp3_id3": (b"ID3", ".mp3"),
    "mp3_no":  (b"\xff\xfb", ".mp3"),
    "mp4":     (b"\x00\x00\x00\x18ftyp", ".mp4"),
    "mp4_2":   (b"\x00\x00\x00\x20ftyp", ".mp4"),
    "wav":     (b"RIFF", ".wav"),  # needs further check
    "avi":     (b"RIFF", ".avi"),  # needs further check
    # Executable
    "exe_mz":  (b"MZ", ".exe"),
    # Java
    "class":   (b"\xca\xfe\xba\xbe", ".class"),
    "jar":     (b"\x50\x4b\x03\x04", ".jar"),  # same as zip
    # Python
    "pyc_31":  (b"\x4f\x0d\x0d\x0a", ".pyc"),
    "pyc_32":  (b"\x6f\x0d\x0d\x0a", ".pyc"),
    "pyc_33":  (b"\x3b\x0d\x0d\x0a", ".pyc"),
    # Crypto / key files
    "pem":     (b"-----BEGIN ", ".pem"),
    # SQLite
    "sqlite":  (b"SQLite format 3\x00", ".sqlite"),
}

# MIME-ish mapping for HTTP Content-Type to extension
CONTENT_TYPE_MAP = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/bmp": ".bmp",
    "image/x-icon": ".ico",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/gzip": ".gz",
    "application/x-gzip": ".gz",
    "application/x-7z-compressed": ".7z",
    "application/x-rar-compressed": ".rar",
    "application/x-tar": ".tar",
    "application/x-bzip2": ".bz2",
    "application/x-xz": ".xz",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/msword": ".doc",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.ms-powerpoint": ".ppt",
    "application/octet-stream": None,  # generic, fall back to magic
    "text/plain": ".txt",
    "text/html": ".html",
    "application/json": ".json",
    "application/xml": ".xml",
    "audio/mpeg": ".mp3",
    "video/mp4": ".mp4",
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
    "application/x-executable": ".elf",
    "application/x-elf": ".elf",
}


def _detect_file_type(data: bytes) -> tuple:
    """Detect file type by magic signature. Returns (type_name, ext) or (None, None)."""
    if len(data) < 4:
        return None, None
    # RIFF-based formats need extra check (WebP, WAV, AVI)
    if data.startswith(b"RIFF") and len(data) >= 12:
        fmt = data[8:12]
        if fmt == b"WEBP":
            return "webp", ".webp"
        elif fmt == b"WAVE":
            return "wav", ".wav"
        elif fmt == b"AVI ":
            return "avi", ".avi"
    # ZIP-based formats: try to distinguish office / jar by inner filenames
    if data.startswith(b"\x50\x4b\x03\x04") and len(data) >= 256:
        head = data[:8192]  # scan larger range for inner filenames
        if b"word/document.xml" in head:
            if b"word/vbaProject.bin" in head:
                return "docm", ".docm"
            return "docx", ".docx"
        if b"xl/workbook.xml" in head:
            if b"xl/vbaProject.bin" in head:
                return "xlsm", ".xlsm"
            return "xlsx", ".xlsx"
        if b"ppt/presentation.xml" in head:
            if b"ppt/vbaProject.bin" in head:
                return "pptm", ".pptm"
            return "pptx", ".pptx"
        if b"META-INF/MANIFEST.MF" in head or b".class" in head:
            return "jar", ".jar"
        return "zip", ".zip"
    for sig_name, (sig, ext) in FILE_SIGNATURES.items():
        if sig_name in ("webp", "wav", "avi"):
            continue
        if data.startswith(sig):
            return sig_name, ext
    return None, None


def _try_detect_size(data: bytes, ftype: str) -> int:
    """Try to detect file size from trailing markers. Returns 0 if unknown."""
    if ftype == "png":
        # Scan for IEND chunk: 4-byte length(0) + "IEND" + 4-byte CRC
        idx = data.find(b"\x00\x00\x00\x00IEND\xaeB`\x82")
        if idx != -1:
            return idx + 12
        return 0
    if ftype in ("zip", "jar", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm"):
        # EOCD signature
        idx = data.rfind(b"\x50\x4b\x05\x06")
        if idx != -1 and len(data) >= idx + 22:
            try:
                cd_size = struct.unpack("<I", data[idx + 12:idx + 16])[0]
                cd_offset = struct.unpack("<I", data[idx + 16:idx + 20])[0]
                comment_len = struct.unpack("<H", data[idx + 20:idx + 22])[0]
                return cd_offset + cd_size + 22 + comment_len
            except struct.error:
                pass
        return 0
    if ftype == "gif":
        idx = data.find(b"\x00\x3b")
        if idx != -1:
            return idx + 2
        return 0
    if ftype in ("jpg", "jpeg"):
        # EOI marker
        idx = data.find(b"\xff\xd9")
        if idx != -1:
            return idx + 2
        return 0
    if ftype == "pdf":
        idx = data.rfind(b"%%EOF")
        if idx != -1:
            return idx + 5
        return 0
    if ftype in ("wav", "avi"):
        # RIFF header contains size at offset 4
        if len(data) >= 8:
            try:
                size = struct.unpack("<I", data[4:8])[0] + 8
                return size
            except struct.error:
                pass
        return 0
    if ftype == "webp":
        if len(data) >= 12:
            try:
                size = struct.unpack("<I", data[4:8])[0] + 8
                return size
            except struct.error:
                pass
        return 0
    if ftype == "gzip":
        # gzip doesn't have a reliable trailer size in the header,
        # but we can try to find the last deflate block and CRC
        return 0
    return 0


def _extract_filename_from_http(http: dict, body: bytes, ftype: str, ext: str) -> str:
    """Try to extract a human-readable filename from HTTP metadata."""
    # 1. Content-Disposition header
    info = http.get("info", "")
    if info:
        # RFC 5987 encoded filename*: filename*=charset'lang'value
        m = re.search(r"filename\*\s*=\s*[^'\s]*'[^'\s]*'([^\"'\;\r\n]+)", info, re.IGNORECASE)
        if m:
            return unquote(m.group(1).strip())
        m = re.search(r'filename\s*=\s*["\']?([^"\';\r\n]+)', info, re.IGNORECASE)
        if m:
            return unquote(m.group(1).strip())
    # 2. Content-Type to guess extension
    ct = ""
    if info:
        m = re.search(r'Content-Type:\s*([^\r\n;]+)', info, re.IGNORECASE)
        if m:
            ct = m.group(1).strip().lower()
    # 3. URI path extension hint (support longer extensions like .docm, .xlsx)
    uri = http.get("uri", "")
    if uri:
        decoded = unquote(uri)
        m = re.search(r'/([^/]+\.[a-zA-Z0-9]{1,8})(?:\?|$)', decoded)
        if m:
            return m.group(1)
    # 4. Fallback generic name
    return None


def _extract_from_http(packets: list) -> list:
    files = []
    # Pre-build TCP stream reassembly map for handling fragmented HTTP responses
    tcp_streams = {}
    for p in packets:
        tcp = p.get("layers", {}).get("tcp", {})
        if not tcp or not tcp.get("payload_hex"):
            continue
        key = f"{p.get('src')}:{p.get('srcPort')}->{p.get('dst')}:{p.get('dstPort')}"
        if key not in tcp_streams:
            tcp_streams[key] = []
        seq = tcp.get("seq")
        tcp_streams[key].append((seq, bytes.fromhex(tcp["payload_hex"])))
    
    # Also build reverse stream map (response stream -> request packet)
    # For matching HTTP responses to their requests
    http_requests = {}
    for p in packets:
        http = p.get("layers", {}).get("http", {})
        if http and http.get("isRequest"):
            key = f"{p.get('src')}:{p.get('srcPort')}->{p.get('dst')}:{p.get('dstPort')}"
            http_requests[key] = p

    for p in packets:
        http = p.get("layers", {}).get("http", {})
        if not http:
            continue
        
        body = b""
        body_hex = http.get("body_hex", "")
        if body_hex and len(body_hex) >= 20:
            # Fast path: body already available in single packet
            body = bytes.fromhex(body_hex)
        elif not http.get("isRequest"):
            # Slow path: TCP-fragmented HTTP response -> reassemble from stream
            headers = http.get("headers", {})
            cl = headers.get("Content-Length", "")
            if cl and cl.isdigit():
                content_length = int(cl)
                # Find the TCP stream for this response
                key = f"{p.get('src')}:{p.get('srcPort')}->{p.get('dst')}:{p.get('dstPort')}"
                if key in tcp_streams:
                    chunks = tcp_streams[key]
                    has_seq = all(c[0] is not None for c in chunks)
                    if has_seq:
                        chunks.sort(key=lambda x: x[0])
                    stream_data = b"".join(c[1] for c in chunks)
                    # Split header and body
                    if b"\r\n\r\n" in stream_data:
                        _, raw_body = stream_data.split(b"\r\n\r\n", 1)
                        body = raw_body[:content_length]
                        body_hex = body.hex()
        
        if not body or len(body) < 10:
            continue
        
        ftype, ext = _detect_file_type(body)
        if not ftype:
            # Also try Content-Type hint even if magic didn't match (e.g. text files)
            info = http.get("info", "")
            ct = ""
            if info:
                m = re.search(r'Content-Type:\s*([^\r\n;]+)', info, re.IGNORECASE)
                if m:
                    ct = m.group(1).strip().lower()
            if ct and ct in CONTENT_TYPE_MAP and CONTENT_TYPE_MAP[ct]:
                ext = CONTENT_TYPE_MAP[ct]
                ftype = ct.split("/")[-1]
                if ftype == "octet-stream":
                    ftype = "unknown"
            else:
                continue
        size = len(body)
        # Try to detect actual file size from trailing markers
        detected = _try_detect_size(body, ftype)
        if detected > 0 and detected <= len(body):
            body = body[:detected]
            size = detected
            body_hex = body.hex()
        # Try to find matching request for responses (to get URI/filename)
        req_http = http
        if not http.get("isRequest"):
            req_key = f"{p.get('dst')}:{p.get('dstPort')}->{p.get('src')}:{p.get('srcPort')}"
            req_pkt = http_requests.get(req_key)
            if req_pkt:
                req_http = req_pkt.get("layers", {}).get("http", {})
        
        fname = _extract_filename_from_http(req_http, body, ftype, ext)
        # If filename has a different extension from magic detection, prefer filename's
        if fname and "." in fname:
            file_ext = fname.split(".")[-1].lower()
            # Map known macro-enabled extensions to correct type
            ext_map = {
                "docm": ".docm", "xlsm": ".xlsm", "pptm": ".pptm",
                "docx": ".docx", "xlsx": ".xlsx", "pptx": ".pptx",
                "zip": ".zip", "jar": ".jar", "gz": ".gz", "png": ".png",
                "jpg": ".jpg", "jpeg": ".jpg", "gif": ".gif", "pdf": ".pdf",
            }
            if file_ext in ext_map:
                ext = ext_map[file_ext]
                ftype = file_ext
        # Build richer source description
        method = req_http.get("method", "")
        uri = req_http.get("uri", "")
        if method and uri:
            source = f"HTTP {method} {unquote(uri)}"
        else:
            source = f"HTTP Packet #{p['index']}"
        files.append({
            "source": source,
            "type": ftype,
            "ext": ext,
            "size": size,
            "hex": body_hex,
            "index": p["index"],
            "filename": fname,
            "protocol": "HTTP",
        })
    return files


def _extract_from_tcp(packets: list) -> list:
    files = []
    streams = {}
    MAX_FILE_SIZE = 524288  # 512 KB cap per file
    for p in packets:
        tcp = p.get("layers", {}).get("tcp", {})
        if not tcp or not tcp.get("payload_hex"):
            continue
        key = f"{p.get('src')}:{p.get('srcPort')}->{p.get('dst')}:{p.get('dstPort')}"
        if key not in streams:
            streams[key] = []
        # Collect seq, payload, and packet index for mapping back
        seq = tcp.get("seq")
        streams[key].append((seq, bytes.fromhex(tcp["payload_hex"]), p["index"]))
    
    # Reassemble each stream
    for key, chunks in streams.items():
        # Sort by seq number if available, fallback to packet order
        has_seq = all(c[0] is not None for c in chunks)
        if has_seq:
            chunks.sort(key=lambda x: x[0])
        
        # Build offset-to-packet-index map
        offset_map = []
        current = 0
        for seq, payload, pkt_idx in chunks:
            offset_map.append((current, current + len(payload), pkt_idx))
            current += len(payload)
        
        data = b"".join(c[1] for c in chunks)
        if len(data) < 10:
            continue
        # Handle HTTP streams: skip headers, extract body, scan for files
        # (needed because TCP-segmented HTTP may have empty body in parser's http layer)
        is_http_stream = data.startswith((b"HTTP/", b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "))
        if is_http_stream:
            body_start = data.find(b"\r\n\r\n")
            if body_start == -1:
                body_start = data.find(b"\n\n")
            if body_start != -1:
                body_start += 4 if data[body_start:body_start+2] == b"\r\n" else 2
                # Respect Content-Length for responses
                cl_match = re.search(rb'Content-Length:\s*(\d+)', data[:body_start], re.IGNORECASE)
                if cl_match:
                    body_len = int(cl_match.group(1))
                    body = data[body_start:body_start + body_len]
                else:
                    body = data[body_start:]
                if len(body) >= 10:
                    # Fast scan for file signatures using bytes.find()
                    seen = set()
                    last_file_end = 0
                    for sig_name, (sig_bytes, ext) in FILE_SIGNATURES.items():
                        offset = 0
                        while True:
                            idx = body.find(sig_bytes, offset)
                            if idx == -1:
                                break
                            if idx < last_file_end:
                                offset = idx + 1
                                continue
                            ftype, detected_ext = _detect_file_type(body[idx:])
                            if not ftype:
                                offset = idx + 1
                                continue
                            detected = _try_detect_size(body[idx:], ftype)
                            if detected > 0:
                                end = idx + min(detected, MAX_FILE_SIZE)
                            else:
                                end = idx + min(262144, len(body) - idx)
                            pos_key = (idx, end)
                            if pos_key in seen:
                                offset = end
                                continue
                            seen.add(pos_key)
                            chunk = body[idx:end]
                            file_offset_in_stream = body_start + idx
                            file_pkt_idx = None
                            for start, end_off, pkt_idx in offset_map:
                                if start <= file_offset_in_stream < end_off:
                                    file_pkt_idx = pkt_idx
                                    break
                            fname = None
                            cd_match = re.search(rb'filename\*?\s*=\s*[^\'\s]*\'[^\'\s]*\'([^"\'\;\r\n]+)', data[:body_start], re.IGNORECASE)
                            if cd_match:
                                fname = unquote(cd_match.group(1).decode('utf-8', errors='ignore').strip())
                            else:
                                cd_match = re.search(rb'filename\s*=\s*["\']?([^"\';\r\n]+)', data[:body_start], re.IGNORECASE)
                                if cd_match:
                                    fname = unquote(cd_match.group(1).decode('utf-8', errors='ignore').strip())
                            files.append({
                                "source": f"HTTP Stream {key}",
                                "type": ftype,
                                "ext": detected_ext or ext,
                                "size": len(chunk),
                                "hex": chunk.hex(),
                                "index": file_pkt_idx,
                                "filename": fname,
                                "protocol": "HTTP",
                            })
                            last_file_end = end
                            offset = end
            continue
        # Fast scan for file signatures using bytes.find()
        seen = set()
        last_file_end = 0
        for sig_name, (sig_bytes, ext) in FILE_SIGNATURES.items():
            offset = 0
            while True:
                idx = data.find(sig_bytes, offset)
                if idx == -1:
                    break
                if idx < last_file_end:
                    offset = idx + 1
                    continue
                ftype, detected_ext = _detect_file_type(data[idx:])
                if not ftype:
                    offset = idx + 1
                    continue
                detected = _try_detect_size(data[idx:], ftype)
                if detected > 0:
                    end = idx + min(detected, MAX_FILE_SIZE)
                else:
                    end = idx + min(262144, len(data) - idx)
                pos_key = (idx, end)
                if pos_key in seen:
                    offset = end
                    continue
                seen.add(pos_key)
                chunk = data[idx:end]
                file_pkt_idx = None
                for start, end_off, pkt_idx in offset_map:
                    if start <= idx < end_off:
                        file_pkt_idx = pkt_idx
                        break
                files.append({
                    "source": f"TCP Stream {key} @0x{idx:x}",
                    "type": ftype,
                    "ext": detected_ext or ext,
                    "size": len(chunk),
                    "hex": chunk.hex(),
                    "index": file_pkt_idx,
                    "filename": None,
                    "protocol": "TCP",
                })
                last_file_end = end
                offset = end
    return files


def _extract_from_udp(packets: list) -> list:
    """Extract files from UDP payloads (e.g. TFTP, DNS large responses)."""
    files = []
    for p in packets:
        udp = p.get("layers", {}).get("udp", {})
        if not udp or not udp.get("payload_hex"):
            continue
        data = bytes.fromhex(udp["payload_hex"])
        if len(data) < 10:
            continue
        ftype, ext = _detect_file_type(data)
        if ftype:
            detected = _try_detect_size(data, ftype)
            if detected > 0:
                data = data[:detected]
            files.append({
                "source": f"UDP Packet #{p['index']}",
                "type": ftype,
                "ext": ext,
                "size": len(data),
                "hex": data.hex(),
                "index": p["index"],
                "filename": None,
                "protocol": "UDP",
            })
    return files


def _dedup_files(files: list) -> list:
    """Remove duplicate files (same source, type, and size)."""
    seen = set()
    result = []
    for f in files:
        key = (f.get("source", ""), f.get("type", ""), f.get("size", 0))
        if key in seen:
            continue
        seen.add(key)
        result.append(f)
    return result


# Max hex preview length in response (full hex available via separate download)
_HEX_PREVIEW_LEN = 65536  # 32KB of hex = 16KB of binary


def analyze(session: dict) -> dict:
    packets = session["packets"]
    http_files = _extract_from_http(packets)
    tcp_files = _extract_from_tcp(packets)
    udp_files = _extract_from_udp(packets)
    all_files = _dedup_files(http_files + tcp_files + udp_files)

    # Truncate hex in response to avoid huge JSON payloads
    for f in all_files:
        hex_data = f.get("hex", "")
        if len(hex_data) > _HEX_PREVIEW_LEN:
            f["hex_preview"] = hex_data[:_HEX_PREVIEW_LEN]
            f["hex_truncated"] = True
        else:
            f["hex_preview"] = hex_data
            f["hex_truncated"] = False
        # Remove full hex from response; kept only in hex_preview
        del f["hex"]

    # Build summary
    proto_counts = {}
    type_counts = {}
    for f in all_files:
        proto_counts[f["protocol"]] = proto_counts.get(f["protocol"], 0) + 1
        type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1

    return {
        "count": len(all_files),
        "files": all_files[:500],
        "by_protocol": proto_counts,
        "by_type": type_counts,
    }


def register(app: FastAPI):
    @app.post("/api/session/{sid}/analyze/files")
    def api_analyze(sid: str):
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        return analyze(sess)
