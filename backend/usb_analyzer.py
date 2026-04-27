"""USB HID traffic analyzer: keyboard and mouse."""
import re
from fastapi import FastAPI, HTTPException
from backend.session import get_session

# USB HID keyboard scan code to char mapping (simplified)
KEYBOARD_MAP = {
    4: 'a', 5: 'b', 6: 'c', 7: 'd', 8: 'e', 9: 'f', 10: 'g', 11: 'h',
    12: 'i', 13: 'j', 14: 'k', 15: 'l', 16: 'm', 17: 'n', 18: 'o', 19: 'p',
    20: 'q', 21: 'r', 22: 's', 23: 't', 24: 'u', 25: 'v', 26: 'w', 27: 'x',
    28: 'y', 29: 'z', 30: '1', 31: '2', 32: '3', 33: '4', 34: '5', 35: '6',
    36: '7', 37: '8', 38: '9', 39: '0',
    40: '\n', 41: '\x1b', 42: '\b', 43: '\t', 44: ' ',
    45: '-', 46: '=', 47: '[', 48: ']', 49: '\\', 51: ';', 52: "'", 53: '`',
    54: ',', 55: '.', 56: '/',
}
SHIFT_KEYBOARD_MAP = {
    4: 'A', 5: 'B', 6: 'C', 7: 'D', 8: 'E', 9: 'F', 10: 'G', 11: 'H',
    12: 'I', 13: 'J', 14: 'K', 15: 'L', 16: 'M', 17: 'N', 18: 'O', 19: 'P',
    20: 'Q', 21: 'R', 22: 'S', 23: 'T', 24: 'U', 25: 'V', 26: 'W', 27: 'X',
    28: 'Y', 29: 'Z', 30: '!', 31: '@', 32: '#', 33: '$', 34: '%', 35: '^',
    36: '&', 37: '*', 38: '(', 39: ')',
    45: '_', 46: '+', 47: '{', 48: '}', 49: '|', 51: ':', 52: '"', 53: '~',
    54: '<', 55: '>', 56: '?',
}


def _parse_usb_keyboard(payload_hex: str) -> str:
    """Parse USB HID keyboard payload (8 bytes per report)."""
    data = bytes.fromhex(payload_hex)
    result = []
    i = 0
    while i + 8 <= len(data):
        report = data[i:i+8]
        modifier = report[0]
        shift = bool(modifier & 0x22)  # left or right shift
        for keycode in report[2:]:
            if keycode == 0:
                continue
            if shift:
                ch = SHIFT_KEYBOARD_MAP.get(keycode, "")
            else:
                ch = KEYBOARD_MAP.get(keycode, "")
            if ch:
                result.append(ch)
        i += 8
    return "".join(result)


def _parse_usb_mouse(payload_hex: str) -> list:
    """Parse USB HID mouse payload. Returns list of (x, y, btn)."""
    data = bytes.fromhex(payload_hex)
    moves = []
    i = 0
    while i + 4 <= len(data):
        report = data[i:i+4]
        btn = report[0]
        x = int.from_bytes(report[1:2], "little", signed=True)
        y = int.from_bytes(report[2:3], "little", signed=True)
        moves.append({"x": x, "y": y, "btn": btn})
        i += 4
    return moves


def analyze(session: dict) -> dict:
    packets = session["packets"]
    keyboard_texts = []
    mouse_streams = {}

    for p in packets:
        proto = p.get("protocol", "")
        if proto != "USB" and proto != "USBHID":
            # Heuristic: check if payload looks like USB HID
            pass

        # Try to find USB data in raw hex or payload
        raw = p.get("_raw", b"")
        hex_data = raw.hex() if raw else ""
        # USB capture often has URB header then HID data
        # Heuristic: look for 8-byte keyboard reports or 4-byte mouse reports
        data = raw if raw else b""
        if len(data) < 4:
            continue

        # Keyboard heuristic: multiple 8-byte blocks with common keycodes
        kb_text = _parse_usb_keyboard(hex_data)
        if kb_text and len(kb_text) > 2:
            keyboard_texts.append({"index": p["index"], "text": kb_text})

        # Mouse heuristic
        mouse_moves = _parse_usb_mouse(hex_data)
        if mouse_moves and len(mouse_moves) > 2:
            key = f"{p.get('src','')}->{p.get('dst','')}"
            if key not in mouse_streams:
                mouse_streams[key] = {"index": p["index"], "moves": []}
            mouse_streams[key]["moves"].extend(mouse_moves)

    # Simplify: aggregate all keyboard texts
    all_kb = "".join(t["text"] for t in keyboard_texts)

    return {
        "keyboard": {
            "found": len(keyboard_texts) > 0,
            "text": all_kb,
            "segments": keyboard_texts[:20],
        },
        "mouse": {
            "found": len(mouse_streams) > 0,
            "streams": [
                {"key": k, "points": len(v["moves"]), "moves": v["moves"][:500]}
                for k, v in mouse_streams.items()
            ],
        },
    }


def register(app: FastAPI):
    @app.post("/api/session/{sid}/analyze/usb")
    def api_analyze(sid: str):
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        return analyze(sess)
