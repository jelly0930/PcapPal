"""Common utilities for analyzers."""
import base64
import binascii
import re


def hex_to_bytes(hex_str: str) -> bytes:
    return binascii.unhexlify(hex_str)


def bytes_to_hex(data: bytes) -> str:
    return binascii.hexlify(data).decode()


def bytes_to_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def safe_ascii(data: bytes) -> str:
    """Printable ASCII with tab/newline/CR preserved, rest as dots."""
    if not data:
        return ""
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data)


def safe_b64decode(s: str) -> bytes:
    try:
        return base64.b64decode(s)
    except Exception:
        return b""


def safe_b32decode(s: str) -> bytes:
    try:
        return base64.b32decode(s.upper())
    except Exception:
        return b""


def rot13(s: str) -> str:
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))


def find_pattern(text: str, patterns: list) -> list:
    """Find all regex matches in text. Returns list of (pattern_name, match)."""
    results = []
    for name, pat in patterns:
        for m in re.finditer(pat, text):
            results.append((name, m.group(0)))
    return results
