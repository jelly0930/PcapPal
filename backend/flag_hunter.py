"""Flag hunter: search for flags with user-defined patterns."""
import base64
import binascii
import re
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException, Request
from backend.session import get_session
from backend.utils import rot13

# Built-in common flag patterns for CTF
BUILTIN_PATTERNS = {
    "flag": re.compile(r"flag\{[^{}]{1,80}\}", re.IGNORECASE),
    "ctf": re.compile(r"ctf\{[^{}]{1,80}\}", re.IGNORECASE),
    "key": re.compile(r"key\{[^{}]{1,80}\}", re.IGNORECASE),
    "picoctf": re.compile(r"picoCTF\{[^{}]{1,80}\}"),
    "htb": re.compile(r"HTB\{[^{}]{1,80}\}"),
    "hctf": re.compile(r"HCTF\{[^{}]{1,80}\}"),
    "hackthebox": re.compile(r"HTB\{[^{}]{1,80}\}"),
    "cyberchallenge": re.compile(r"CC\{[^{}]{1,80}\}"),
    "md5": re.compile(r"\b[a-f0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b"),
}

# Patterns that produce too many false positives when searched in raw hex.
HEX_NOISE_PATTERNS = {"md5", "sha1", "sha256"}

# Patterns that require '{' character to match (CTF flag formats)
BRACE_PATTERNS = {"flag", "ctf", "key", "picoctf", "htb", "hctf", "hackthebox", "cyberchallenge"}

# Human-readable descriptions for UI
default_rule_descriptions = [
    ("flag{...}", r"flag\{[^{}]{1,80}\}"),
    ("ctf{...}", r"ctf\{[^{}]{1,80}\}"),
    ("key{...}", r"key\{[^{}]{1,80}\}"),
    ("picoCTF{...}", r"picoCTF\{[^{}]{1,80}\}"),
    ("HTB{...} / HCTF{...}", r"(HTB|HCTF)\{[^{}]{1,80}\}"),
    ("CC{...}", r"CC\{[^{}]{1,80}\}"),
    ("MD5 hash", r"\b[a-f0-9]{32}\b"),
    ("SHA1 hash", r"\b[a-f0-9]{40}\b"),
    ("SHA256 hash", r"\b[a-f0-9]{64}\b"),
]


def _compile_pattern(pat: str, is_regex: bool = True):
    if is_regex:
        try:
            return re.compile(pat, re.IGNORECASE)
        except re.error:
            return None
    else:
        return re.compile(re.escape(pat), re.IGNORECASE)


def _search_with_pattern(text: str, pattern_name: str, compiled, ctx: str, encoding: str = "plain", pkt_index: int = 0) -> list:
    results = []
    if compiled is None:
        return results
    for m in compiled.finditer(text):
        results.append({
            "type": pattern_name,
            "match": m.group(0),
            "context": ctx,
            "encoding": encoding,
            "index": pkt_index,
        })
    return results


def _has_brace(text: str) -> bool:
    """Fast check if text contains '{' (common in CTF flag formats)."""
    return "{" in text


def _has_flag_hex_sig(text: str) -> bool:
    """Check if hex text contains 'flag' in hex."""
    return "666c6167" in text


def analyze(session: dict, user_patterns: List[Dict[str, Any]] = None) -> list:
    packets = session["packets"]
    results = []

    # Build pattern list
    patterns = []
    if user_patterns:
        for up in user_patterns:
            name = up.get("name", "custom")
            pat_str = up.get("pattern", "")
            is_regex = up.get("regex", True)
            if not pat_str:
                continue
            compiled = _compile_pattern(pat_str, is_regex)
            if compiled:
                patterns.append((name, compiled))
    else:
        patterns = list(BUILTIN_PATTERNS.items())

    # Separate noise patterns (only search in ASCII, not raw hex)
    noise_names = set(HEX_NOISE_PATTERNS)
    ascii_patterns = patterns
    hex_patterns = [(n, c) for n, c in patterns if n not in noise_names]

    # Categorize patterns by whether they need '{'
    flag_patterns = [(n, c) for n, c in ascii_patterns if n in BRACE_PATTERNS]
    other_ascii_patterns = [(n, c) for n, c in ascii_patterns if n not in BRACE_PATTERNS]
    # Pre-compile chunk regexes
    b64_chunk_re = re.compile(r"[A-Za-z0-9+/]{20,120}=?==?")
    hex_chunk_re = re.compile(r"[0-9a-fA-F]{20,120}")

    for p in packets:
        ctx = f"Packet #{p['index']} ({p.get('protocol','?')})"

        # Lazy-generate ascii/hex from raw
        raw = p.get("_raw", b"")
        if "ascii" in p:
            ascii_text = p["ascii"]
            hex_text = p.get("hex", "")
        else:
            ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
            hex_text = raw.hex()

        has_brace = _has_brace(ascii_text)
        has_flag_hex = _has_flag_hex_sig(hex_text)

        # --- Full packet search ---
        # Flag patterns (need '{')
        if has_brace or user_patterns:
            for name, compiled in flag_patterns:
                results.extend(_search_with_pattern(ascii_text, name, compiled, ctx, "plain", p["index"]))

        # Non-flag ascii patterns (MD5/SHA) - always search in ascii
        for name, compiled in other_ascii_patterns:
            results.extend(_search_with_pattern(ascii_text, name, compiled, ctx, "plain", p["index"]))

        # Hex search (only non-noise patterns)
        if has_flag_hex or user_patterns:
            for name, compiled in hex_patterns:
                results.extend(_search_with_pattern(hex_text, name, compiled, ctx, "hex", p["index"]))

        # Base64/hex-decode search and rot13 - only if brace present or user patterns
        if has_brace or user_patterns:
            # Base64 decode search
            b64_chunks = b64_chunk_re.findall(ascii_text)
            for chunk in b64_chunks:
                try:
                    decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for name, compiled in ascii_patterns:
                    for r in _search_with_pattern(decoded, name, compiled, ctx, "base64", p["index"]):
                        r["encoded"] = chunk
                        results.append(r)

            # Hex-decode chunks from ASCII text
            hex_chunks = hex_chunk_re.findall(ascii_text)
            for chunk in hex_chunks:
                if len(chunk) % 2 != 0:
                    continue
                try:
                    decoded = binascii.unhexlify(chunk).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for name, compiled in ascii_patterns:
                    for r in _search_with_pattern(decoded, name, compiled, ctx, "hex-decode", p["index"]):
                        r["encoded"] = chunk
                        results.append(r)

            # rot13
            rot = rot13(ascii_text)
            for name, compiled in ascii_patterns:
                results.extend(_search_with_pattern(rot, name, compiled, ctx, "rot13", p["index"]))

        # --- Layer payload search ---
        for layer_name in ["tcp", "udp", "icmp", "dns"]:
            layer = p.get("layers", {}).get(layer_name, {})
            payload_ascii = layer.get("payload_ascii", "")
            payload_hex = layer.get("payload_hex", "")
            if not payload_ascii:
                continue
            lctx = f"Packet #{p['index']} {layer_name.upper()} payload"
            layer_has_brace = _has_brace(payload_ascii)

            if layer_has_brace or user_patterns:
                for name, compiled in flag_patterns:
                    results.extend(_search_with_pattern(payload_ascii, name, compiled, lctx, "plain", p["index"]))

            for name, compiled in other_ascii_patterns:
                results.extend(_search_with_pattern(payload_ascii, name, compiled, lctx, "plain", p["index"]))

            if payload_hex and (layer_has_brace or user_patterns):
                for name, compiled in hex_patterns:
                    results.extend(_search_with_pattern(payload_hex, name, compiled, lctx, "hex", p["index"]))

        # --- HTTP body search ---
        http = p.get("layers", {}).get("http", {})
        body_ascii = http.get("body_ascii", "")
        body_hex = http.get("body_hex", "")
        if body_ascii:
            lctx = f"Packet #{p['index']} HTTP body"
            body_has_brace = _has_brace(body_ascii)

            if body_has_brace or user_patterns:
                for name, compiled in flag_patterns:
                    results.extend(_search_with_pattern(body_ascii, name, compiled, lctx, "plain", p["index"]))

            for name, compiled in other_ascii_patterns:
                results.extend(_search_with_pattern(body_ascii, name, compiled, lctx, "plain", p["index"]))

            if body_hex and (body_has_brace or user_patterns):
                for name, compiled in hex_patterns:
                    results.extend(_search_with_pattern(body_hex, name, compiled, lctx, "hex", p["index"]))

    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        key = (r.get("match", ""), r.get("index", 0), r.get("encoding", ""))
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def register(app: FastAPI):
    @app.post("/api/session/{sid}/analyze/flag")
    async def api_analyze(sid: str, request: Request):
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        try:
            body = await request.json()
        except Exception:
            body = {}
        user_patterns = body.get("patterns") if body else None
        return {"results": analyze(sess, user_patterns), "defaultRules": default_rule_descriptions}
