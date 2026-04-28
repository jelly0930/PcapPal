"""Session management: hold parsed packets in memory with indexes."""
import os
import uuid
import time
import threading
from typing import Dict, Any, Optional

SESSIONS: Dict[str, Dict[str, Any]] = {}
SESSION_TIMEOUT = 3600  # 1 hour
_CLEANUP_INTERVAL = 300  # 5 minutes


def _cleanup_expired():
    """Delete expired sessions and their temp files."""
    now = time.time()
    to_delete = [
        sid for sid, sess in SESSIONS.items()
        if now - sess["created"] > SESSION_TIMEOUT
    ]
    for sid in to_delete:
        sess = SESSIONS.pop(sid, None)
        if sess:
            _delete_temp_file(sess.get("original_path"))


def _delete_temp_file(path: Optional[str]):
    if path and os.path.exists(path):
        try:
            os.unlink(path)
        except OSError:
            pass


def _cleanup_loop():
    while True:
        time.sleep(_CLEANUP_INTERVAL)
        _cleanup_expired()


# Start background cleanup thread
_cleanup_thread = threading.Thread(target=_cleanup_loop, daemon=True)
_cleanup_thread.start()


def create_session() -> str:
    sid = str(uuid.uuid4())[:16]
    SESSIONS[sid] = {
        "created": time.time(),
        "packets": [],
        "filename": "",
    }
    return sid


def get_session(sid: str) -> Optional[Dict[str, Any]]:
    sess = SESSIONS.get(sid)
    if sess and time.time() - sess["created"] > SESSION_TIMEOUT:
        _delete_temp_file(sess.get("original_path"))
        del SESSIONS[sid]
        return None
    return sess


def store_packets(sid: str, packets: list, filename: str = "", original_path: str = ""):
    sess = get_session(sid)
    if not sess:
        return
    # Compute delta (time since previous packet) for each packet
    for i, p in enumerate(packets):
        if i == 0:
            p["delta"] = 0.0
        else:
            p["delta"] = round(p["timestamp"] - packets[i - 1]["timestamp"], 6)

    # Build indexes for fast lookups
    packet_by_index: Dict[int, dict] = {}
    packets_by_protocol: Dict[str, list] = {}
    for p in packets:
        idx = p["index"]
        packet_by_index[idx] = p
        proto = p.get("protocol", "UNKNOWN")
        packets_by_protocol.setdefault(proto, []).append(p)

    sess["packets"] = packets
    sess["packet_by_index"] = packet_by_index
    sess["packets_by_protocol"] = packets_by_protocol
    sess["filename"] = filename
    sess["first_timestamp"] = packets[0]["timestamp"] if packets else 0.0
    sess["original_path"] = original_path


def rebuild_indexes(sess: Dict[str, Any]):
    """Rebuild packet_by_index and packets_by_protocol from sess["packets"]."""
    packets = sess.get("packets", [])
    packet_by_index: Dict[int, dict] = {}
    packets_by_protocol: Dict[str, list] = {}
    for p in packets:
        idx = p["index"]
        packet_by_index[idx] = p
        proto = p.get("protocol", "UNKNOWN")
        packets_by_protocol.setdefault(proto, []).append(p)
    sess["packet_by_index"] = packet_by_index
    sess["packets_by_protocol"] = packets_by_protocol
