"""Webshell payload decryptor - rule engine for common webshell families."""
import re
import base64
import urllib.parse
from typing import Dict, Any, Optional, Callable, List

# Optional AES support
try:
    from Crypto.Cipher import AES
    _HAS_AES = True
except ImportError:
    _HAS_AES = False


def _safe_unpad(data: bytes) -> bytes:
    """Remove PKCS5/PKCS7 padding."""
    if not data:
        return data
    pad_len = data[-1]
    if 1 <= pad_len <= 16 and data.endswith(bytes([pad_len]) * pad_len):
        return data[:-pad_len]
    return data


def _try_decode(data: bytes, encodings=("utf-8", "gbk", "gb2312", "latin-1")) -> str:
    """Try multiple encodings to decode bytes."""
    for enc in encodings:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="ignore")


def _is_reasonable_text(text: str, min_printable_ratio: float = 0.7) -> bool:
    """Check if decrypted text looks reasonable (mostly printable)."""
    if not text or len(text) < 4:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    ratio = printable / len(text)
    return ratio >= min_printable_ratio


# ============================================================================
# Decryptors
# ============================================================================

def decrypt_asp_bypass(payload: str, key: str) -> str:
    """ASP bypass webshell: Base64 decode → XOR with repeating key.

    VBScript logic:
        For i=1 To size
            BinaryStream.WriteText chrw(ascb(midb(content,i,1)) Xor Asc(Mid(key,(i mod keySize)+1,1)))
        Next
    """
    try:
        raw = base64.b64decode(payload)
    except Exception as e:
        return f"[Base64 decode failed: {e}]"
    if not key:
        return "[Key required for ASP XOR decryption]"
    key_bytes = key.encode("latin-1")
    # VBScript: Mid(key, (i mod keySize)+1, 1) is 1-indexed, so offset by +1
    result = bytes([raw[i] ^ key_bytes[(i + 1) % len(key_bytes)] for i in range(len(raw))])
    return _try_decode(result)


def decrypt_jspx_aes(payload: str, key: str) -> str:
    """JSPX AES webshell: Base64 decode → AES/ECB/PKCS5Padding decrypt."""
    if not _HAS_AES:
        return "[pycryptodome required for AES decryption]"
    if not key:
        return "[Key required for JSPX AES decryption]"
    try:
        raw = base64.b64decode(payload)
        cipher = AES.new(key.encode("utf-8"), AES.MODE_ECB)
        decrypted = cipher.decrypt(raw)
        decrypted = _safe_unpad(decrypted)
        return _try_decode(decrypted)
    except Exception as e:
        return f"[AES decrypt failed: {e}]"


def decrypt_jspx_eval(payload: str, _key: str = "") -> str:
    """JSPX eval webshell: the payload is VBScript/ASP code embedded in eval().

    Some JSPX shells use eval("Ex"&cHr(101)&"cute(...)") to drop ASP code.
    The actual command is often hex-encoded inside the eval string.
    """
    try:
        # URL decode first if needed
        s = urllib.parse.unquote(payload)
        # Look for hex-encoded ASP code: strings of hex digits inside quotes
        hex_chunks = re.findall(r'["\']([0-9a-fA-F]{100,})["\']', s)
        if hex_chunks:
            decoded_parts = []
            for chunk in hex_chunks:
                try:
                    decoded = bytes.fromhex(chunk)
                    text = _try_decode(decoded)
                    if _is_reasonable_text(text):
                        decoded_parts.append(text)
                except Exception:
                    continue
            if decoded_parts:
                return "\n---\n".join(decoded_parts)
        # If no hex chunks, return the raw decoded string for inspection
        return s[:2000]
    except Exception as e:
        return f"[JSPX eval decode failed: {e}]"


def decrypt_php_eval_base64(payload: str, _key: str = "") -> str:
    """PHP eval+base64 webshell: extract inner string → urldecode → strrev → base64 decode."""
    try:
        # Case 1: full PHP expression like eval(base64_decode(strrev(urldecode('...'))))
        m = re.search(r"urldecode\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", payload)
        if m:
            inner = m.group(1)
        else:
            inner = payload

        # Double URL decode if needed
        s = urllib.parse.unquote(inner)
        if "%" in s:
            s = urllib.parse.unquote(s)

        # Try strrev then base64
        candidates = []
        if s.startswith("="):
            # Padding moved to front by strrev - fix it
            s_fixed = s[1:] + "="
            candidates.append(s_fixed[::-1])
        candidates.append(s[::-1])

        for candidate in candidates:
            for pad in ["", "=", "=="]:
                try:
                    decoded = base64.b64decode(candidate + pad)
                    text = _try_decode(decoded)
                    if _is_reasonable_text(text) and len(text) > 5:
                        return text
                except Exception:
                    continue
        return "[Could not decode PHP payload]"
    except Exception as e:
        return f"[PHP decode failed: {e}]"


def decrypt_php_simple_base64(payload: str, _key: str = "") -> str:
    """PHP simple base64: direct base64 decode."""
    try:
        for pad in ["", "=", "=="]:
            try:
                decoded = base64.b64decode(payload + pad)
                text = _try_decode(decoded)
                if _is_reasonable_text(text) and len(text) > 5:
                    return text
            except Exception:
                continue
        return "[Could not decode base64 payload]"
    except Exception as e:
        return f"[Base64 decode failed: {e}]"


def decrypt_php_xor(payload: str, key: str) -> str:
    """PHP XOR: try single-byte and multi-byte XOR."""
    try:
        raw = base64.b64decode(payload)
    except Exception:
        # Maybe it's hex encoded
        try:
            raw = bytes.fromhex(payload)
        except Exception:
            raw = payload.encode("latin-1", errors="ignore")

    if key:
        key_bytes = key.encode("latin-1", errors="ignore")
        result = bytes([raw[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(raw))])
        text = _try_decode(result)
        if _is_reasonable_text(text):
            return text
        return f"[XOR with provided key did not yield readable text]\n\nRaw hex:\n{result[:200].hex()}"

    # Try common single-byte keys
    best = ""
    best_score = 0
    for k in range(256):
        result = bytes([b ^ k for b in raw])
        try:
            text = result.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = result.decode("latin-1")
            except Exception:
                continue
        score = sum(1 for c in text if c.isprintable() or c in " \r\n\t")
        if score > best_score and _is_reasonable_text(text):
            best_score = score
            best = text

    if best:
        return best
    return "[Could not auto-detect XOR key]"


def decrypt_generic(payload: str, key: str = "") -> str:
    """Generic fallback: try base64, hex, XOR."""
    results = []

    # Try base64
    try:
        raw = base64.b64decode(payload)
        text = _try_decode(raw)
        if _is_reasonable_text(text) and len(text) > 5:
            results.append(("base64", text))
    except Exception:
        pass

    # Try hex
    try:
        raw = bytes.fromhex(payload)
        text = _try_decode(raw)
        if _is_reasonable_text(text) and len(text) > 5:
            results.append(("hex", text))
    except Exception:
        pass

    # Try XOR with key if provided
    if key:
        try:
            raw = base64.b64decode(payload)
        except Exception:
            try:
                raw = bytes.fromhex(payload)
            except Exception:
                raw = payload.encode("latin-1", errors="ignore")
        key_bytes = key.encode("latin-1", errors="ignore")
        result = bytes([raw[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(raw))])
        text = _try_decode(result)
        if _is_reasonable_text(text) and len(text) > 5:
            results.append(("xor", text))

    if results:
        return "\n\n".join(f"[{name}]\n{text[:500]}" for name, text in results)
    return "[No generic decode succeeded]"


# ============================================================================
# Rule engine
# ============================================================================

WEBSHELL_DECRYPT_RULES: Dict[str, Dict[str, Any]] = {
    "asp_bypass": {
        "name": "ASP Bypass",
        "detect_patterns": [
            r'decryption\s*\(\s*content\s*,\s*isBin\s*\)',
            r'Base64Decode\s*\(',
        ],
        "key_patterns": [
            r'key\s*=\s*["\']([a-f0-9]+)["\']',
        ],
        "decrypt": decrypt_asp_bypass,
        "description": "Base64 + XOR with repeating key (VBScript)",
    },
    "jspx_aes": {
        "name": "JSPX AES",
        "detect_patterns": [
            r'javax\.crypto\.Cipher\.getInstance\s*\(\s*"AES"\s*\)',
            r'SecretKeySpec',
        ],
        "key_patterns": [
            r'String\s+xc\s*=\s*["\']([a-f0-9]+)["\']',
            r'String\s+pass\s*=\s*["\']([^"\']+)["\']',
        ],
        "decrypt": decrypt_jspx_aes,
        "description": "Base64 + AES/ECB/PKCS5Padding",
    },
    "jspx_eval": {
        "name": "JSPX Eval",
        "detect_patterns": [
            r'eval\s*\(\s*["\']Ex["\']\s*&\s*cHr\s*\(\s*101\s*\)',
            r'eval\s*\(\s*["\']Ex["\']\s*&\s*["\']cute',
        ],
        "key_patterns": [],
        "decrypt": decrypt_jspx_eval,
        "description": "JSPX eval Execute dropper (hex-encoded ASP)",
    },
    "php_eval_base64": {
        "name": "PHP Eval+Base64",
        "detect_patterns": [
            r'eval\s*\(\s*base64_decode\s*\(\s*strrev\s*\(\s*urldecode',
            r'eval\s*\(\s*base64_decode\s*\(\s*urldecode',
        ],
        "key_patterns": [],
        "decrypt": decrypt_php_eval_base64,
        "description": "URL decode → strrev → Base64 decode",
    },
    "php_simple_eval": {
        "name": "PHP Simple Eval",
        "detect_patterns": [
            r'eval\s*\(\s*\$_POST\s*\[',
            r'assert\s*\(\s*\$_POST\s*\[',
            r'eval\s*\(\s*\$_REQUEST\s*\[',
        ],
        "key_patterns": [],
        "decrypt": decrypt_php_eval_base64,
        "description": "Simple PHP eval/assert with POST param",
    },
    "php_simple_base64": {
        "name": "PHP Simple Base64",
        "detect_patterns": [
            r'eval\s*\(\s*base64_decode\s*\(',
            r'assert\s*\(\s*base64_decode\s*\(',
        ],
        "key_patterns": [],
        "decrypt": decrypt_php_simple_base64,
        "description": "Direct Base64 decode",
    },
    "php_xor": {
        "name": "PHP XOR",
        "detect_patterns": [
            r'base64_decode\s*\(\s*\$_POST',
            r'base64_decode\s*\(\s*\$_REQUEST',
        ],
        "key_patterns": [
            r'["\']([a-zA-Z0-9]{4,32})["\']\s*\)\s*;',
            r'\$key\s*=\s*["\']([^"\']+)["\']',
        ],
        "decrypt": decrypt_php_xor,
        "description": "Base64/Hex + XOR with key",
    },
    "generic": {
        "name": "Generic",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_generic,
        "description": "Try base64, hex, XOR automatically",
    },
}


def detect_webshell_type(body: str, is_request: bool = False) -> Optional[str]:
    """Detect webshell family from response/request body."""
    for rule_id, rule in WEBSHELL_DECRYPT_RULES.items():
        if rule_id == "generic":
            continue
        matched = 0
        for pat in rule["detect_patterns"]:
            if re.search(pat, body, re.IGNORECASE):
                matched += 1
        # Need at least one pattern to match
        if matched >= 1:
            return rule_id
    return None


def extract_key(body: str, rule_id: str) -> Optional[str]:
    """Extract decryption key from response/request body."""
    rule = WEBSHELL_DECRYPT_RULES.get(rule_id)
    if not rule:
        return None
    for pat in rule.get("key_patterns", []):
        m = re.search(pat, body)
        if m:
            return m.group(1)
    return None


def decrypt_payload(payload: str, rule_id: str, key: str = "") -> str:
    """Decrypt a payload using the given rule."""
    rule = WEBSHELL_DECRYPT_RULES.get(rule_id)
    if not rule:
        return "[Unknown webshell type]"
    decrypt_fn: Callable = rule["decrypt"]
    try:
        if key:
            return decrypt_fn(payload, key)
        else:
            return decrypt_fn(payload)
    except Exception as e:
        return f"[Decrypt Error: {e}]"


def _extract_param_value(body: str, param_name: str) -> Optional[str]:
    """Extract a parameter value from form-urlencoded body."""
    m = re.search(rf'(?:^|&){re.escape(param_name)}=([^&\s]+)', body)
    if m:
        return urllib.parse.unquote(m.group(1))
    return None


def _find_base64_params(body: str) -> List[tuple]:
    """Find parameters with base64-looking values in form body."""
    results = []
    for m in re.finditer(r'([a-zA-Z0-9_]+)=([A-Za-z0-9+/=%]+)', body):
        name, val = m.group(1), urllib.parse.unquote(m.group(2))
        if len(val) >= 20 and re.match(r'^[A-Za-z0-9+/=]+$', val):
            results.append((name, val))
    return results


def _find_all_params(body: str) -> List[tuple]:
    """Find all parameters in form-urlencoded body."""
    results = []
    for m in re.finditer(r'([a-zA-Z0-9_]+)=([^&\s]*)', body):
        name, val = m.group(1), urllib.parse.unquote(m.group(2))
        if len(val) >= 8:
            results.append((name, val))
    return results


def analyze_transaction(tx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Analyze a single HTTP transaction for webshell decryption.

    Returns None if no webshell detected, otherwise returns metadata dict.
    """
    resp_body = tx.get("responseBody", "") or ""
    req_body = tx.get("requestBody", "") or ""
    uri = tx.get("uri", "") or ""

    # URL-decode request body for pattern matching (many shells URL-encode their payloads)
    req_body_decoded = urllib.parse.unquote(req_body)

    # Try detect from response first, then request (both raw and decoded)
    ws_type = detect_webshell_type(resp_body, is_request=False)
    source = "response"
    if not ws_type:
        ws_type = detect_webshell_type(req_body, is_request=True)
        source = "request"
    if not ws_type:
        ws_type = detect_webshell_type(req_body_decoded, is_request=True)
        source = "request"

    # Heuristic: common webshell extensions with heavy base64 in request
    if not ws_type and uri:
        if re.search(r'\.(asp|jsp|jspx|php)\b', uri, re.I):
            b64_params = _find_base64_params(req_body)
            if b64_params:
                ws_type = "unknown_base64"

    if not ws_type:
        return None

    key = ""
    if ws_type in WEBSHELL_DECRYPT_RULES:
        key = extract_key(resp_body, ws_type) or extract_key(req_body, ws_type) or extract_key(req_body_decoded, ws_type) or ""

    return {
        "type": ws_type,
        "type_name": WEBSHELL_DECRYPT_RULES.get(ws_type, {}).get("name", ws_type),
        "key": key,
        "description": WEBSHELL_DECRYPT_RULES.get(ws_type, {}).get("description", ""),
        "source": source,
    }


def decrypt_transaction(tx: Dict[str, Any], ws_info: Dict[str, Any]) -> Dict[str, Any]:
    """Decrypt the request payload of a webshell transaction.

    Returns a dict with decryption results for each parameter.
    """
    rule_id = ws_info["type"]
    key = ws_info.get("key", "")
    req_body = tx.get("requestBody", "") or ""
    uri = tx.get("uri", "") or ""
    method = tx.get("method", "") or ""
    results: List[Dict[str, str]] = []

    if rule_id == "asp_bypass":
        for param_name in ["plryormg41", "content", "payload", "data"]:
            payload = _extract_param_value(req_body, param_name)
            if payload and len(payload) >= 20:
                decrypted = decrypt_asp_bypass(payload, key)
                results.append({
                    "param": param_name,
                    "original": payload[:200],
                    "original_len": len(payload),
                    "decrypted": decrypted,
                    "decrypted_len": len(decrypted),
                })
                break
        if not results:
            for param_name, payload in _find_base64_params(req_body):
                if len(payload) >= 20:
                    decrypted = decrypt_asp_bypass(payload, key)
                    results.append({
                        "param": param_name,
                        "original": payload[:200],
                        "original_len": len(payload),
                        "decrypted": decrypted,
                        "decrypted_len": len(decrypted),
                    })

    elif rule_id == "jspx_aes":
        for param_name in ["vhdb1uiipf", "pass", "payload", "data", "cmd"]:
            payload = _extract_param_value(req_body, param_name)
            if payload and len(payload) >= 20:
                decrypted = decrypt_jspx_aes(payload, key)
                results.append({
                    "param": param_name,
                    "original": payload[:200],
                    "original_len": len(payload),
                    "decrypted": decrypted,
                    "decrypted_len": len(decrypted),
                })
                break
        if not results:
            for param_name, payload in _find_base64_params(req_body):
                if len(payload) >= 20:
                    decrypted = decrypt_jspx_aes(payload, key)
                    results.append({
                        "param": param_name,
                        "original": payload[:200],
                        "original_len": len(payload),
                        "decrypted": decrypted,
                        "decrypted_len": len(decrypted),
                    })

    elif rule_id == "jspx_eval":
        for param_name in ["vhdb1uiipf", "pass", "payload", "data", "cmd"]:
            payload = _extract_param_value(req_body, param_name)
            if payload and len(payload) >= 20:
                decrypted = decrypt_jspx_eval(payload, key)
                results.append({
                    "param": param_name,
                    "original": payload[:200],
                    "original_len": len(payload),
                    "decrypted": decrypted,
                    "decrypted_len": len(decrypted),
                })
                break
        if not results:
            for param_name, payload in _find_all_params(req_body):
                if len(payload) >= 20:
                    decrypted = decrypt_jspx_eval(payload, key)
                    results.append({
                        "param": param_name,
                        "original": payload[:200],
                        "original_len": len(payload),
                        "decrypted": decrypted,
                        "decrypted_len": len(decrypted),
                    })

    elif rule_id in ("php_eval_base64", "php_simple_eval"):
        m = re.search(
            r"([a-zA-Z0-9_]+)=(eval%28base64_decode%28strrev%28urldecode%28%27[^%]+%27%29%29%29%29)",
            req_body,
        )
        if m:
            payload = urllib.parse.unquote(m.group(2))
            decrypted = decrypt_php_eval_base64(payload)
            results.append({
                "param": m.group(1),
                "original": payload[:200],
                "original_len": len(payload),
                "decrypted": decrypted,
                "decrypted_len": len(decrypted),
            })
        if not results:
            for param_name, payload in _find_base64_params(req_body):
                if len(payload) >= 20:
                    decrypted = decrypt_php_eval_base64(payload)
                    if decrypted and not decrypted.startswith("["):
                        results.append({
                            "param": param_name,
                            "original": payload[:200],
                            "original_len": len(payload),
                            "decrypted": decrypted,
                            "decrypted_len": len(decrypted),
                        })

    elif rule_id == "php_simple_base64":
        for param_name, payload in _find_base64_params(req_body):
            if len(payload) >= 20:
                decrypted = decrypt_php_simple_base64(payload)
                if decrypted and not decrypted.startswith("["):
                    results.append({
                        "param": param_name,
                        "original": payload[:200],
                        "original_len": len(payload),
                        "decrypted": decrypted,
                        "decrypted_len": len(decrypted),
                    })

    elif rule_id == "php_xor":
        for param_name, payload in _find_base64_params(req_body):
            if len(payload) >= 20:
                decrypted = decrypt_php_xor(payload, key)
                results.append({
                    "param": param_name,
                    "original": payload[:200],
                    "original_len": len(payload),
                    "decrypted": decrypted,
                    "decrypted_len": len(decrypted),
                })

    elif rule_id == "unknown_base64":
        for param_name, payload in _find_base64_params(req_body):
            if len(payload) >= 20:
                # Try all known decryptors
                for rid, rule in WEBSHELL_DECRYPT_RULES.items():
                    if rid in ("generic", "unknown_base64"):
                        continue
                    decrypted = rule["decrypt"](payload, key)
                    if decrypted and not decrypted.startswith("[") and len(decrypted) > 5:
                        results.append({
                            "param": param_name,
                            "original": payload[:200],
                            "original_len": len(payload),
                            "decrypted": decrypted,
                            "decrypted_len": len(decrypted),
                            "matched_rule": rid,
                        })
                        break
                else:
                    # Try generic fallback
                    decrypted = decrypt_generic(payload, key)
                    if decrypted and not decrypted.startswith("["):
                        results.append({
                            "param": param_name,
                            "original": payload[:200],
                            "original_len": len(payload),
                            "decrypted": decrypted,
                            "decrypted_len": len(decrypted),
                            "matched_rule": "generic",
                        })

    return {
        "transaction_id": tx.get("id"),
        "uri": uri,
        "method": method,
        "type": rule_id,
        "type_name": ws_info.get("type_name", rule_id),
        "key": key,
        "results": results,
    }


def analyze_session(http_transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze all HTTP transactions in a session for webshell decryption."""
    findings: List[Dict[str, Any]] = []
    for tx in http_transactions:
        ws_info = analyze_transaction(tx)
        if ws_info:
            decrypted = decrypt_transaction(tx, ws_info)
            if decrypted.get("results"):
                findings.append(decrypted)
    return findings


# ============================================================================
# FastAPI registration helper
# ============================================================================

def register(app):
    """Register webshell decryptor FastAPI routes."""
    from fastapi import HTTPException
    from backend.session import get_session

    @app.get("/api/session/{sid}/webshell/decrypt")
    def get_webshell_decrypt(sid: str):
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        import main
        transactions = main._get_http_transactions_cached(sess)
        findings = analyze_session(transactions)
        supported = []
        for rid, rule in WEBSHELL_DECRYPT_RULES.items():
            supported.append({
                "id": rid,
                "name": rule["name"],
                "description": rule.get("description", ""),
            })
        return {
            "count": len(findings),
            "findings": findings,
            "supported_types": supported,
        }

    @app.post("/api/session/{sid}/webshell/decrypt/{tx_id}")
    def post_webshell_decrypt(sid: str, tx_id: int, body: dict = None):
        if body is None:
            body = {}
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        import main
        transactions = main._get_http_transactions_cached(sess)
        tx = None
        for t in transactions:
            if t.get("id") == tx_id:
                tx = t
                break
        if not tx:
            raise HTTPException(status_code=404, detail="Transaction not found")
        ws_info = analyze_transaction(tx)
        if not ws_info:
            raise HTTPException(status_code=404, detail="No webshell detected in this transaction")
        custom_key = body.get("key", "")
        if custom_key:
            ws_info["key"] = custom_key
        result = decrypt_transaction(tx, ws_info)
        # Return flat structure for frontend compatibility
        return {
            "transaction_id": tx_id,
            "uri": result.get("uri", ""),
            "method": result.get("method", ""),
            "type": result.get("type", ""),
            "type_name": result.get("type_name", ""),
            "key": ws_info.get("key", ""),
            "results": result.get("results", []),
        }

    @app.post("/api/session/{sid}/webshell/decrypt/{tx_id}/manual")
    def post_webshell_manual_decrypt(sid: str, tx_id: int, body: dict = None):
        """Manual webshell decryption: user specifies type and key, bypassing auto-detection."""
        if body is None:
            body = {}
        ws_type = body.get("type", "auto")
        ws_key = body.get("key", "")
        ws_param = body.get("param", "")  # optional: specific param name

        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        import main
        transactions = main._get_http_transactions_cached(sess)
        tx = None
        for t in transactions:
            if t.get("id") == tx_id:
                tx = t
                break
        if not tx:
            raise HTTPException(status_code=404, detail="Transaction not found")

        req_body = tx.get("requestBody", "") or ""

        if ws_type == "auto":
            # Try all rules, return the best result from each
            results = []
            for rid, rule in WEBSHELL_DECRYPT_RULES.items():
                if rid == "generic":
                    continue
                ws_info = {"type": rid, "type_name": rule["name"], "key": ws_key}
                dec_result = decrypt_transaction(tx, ws_info)
                if dec_result.get("results"):
                    results.append({
                        "type": rid,
                        "type_name": rule["name"],
                        "key": ws_key,
                        "results": dec_result["results"],
                    })
            # Also try generic
            if not results:
                ws_info = {"type": "generic", "type_name": "Generic", "key": ws_key}
                dec_result = decrypt_transaction(tx, ws_info)
                if dec_result.get("results"):
                    results.append({
                        "type": "generic",
                        "type_name": "Generic",
                        "key": ws_key,
                        "results": dec_result["results"],
                    })
            return {
                "transaction_id": tx_id,
                "mode": "auto",
                "attempts": results,
            }

        # Specific type
        rule = WEBSHELL_DECRYPT_RULES.get(ws_type)
        if not rule:
            raise HTTPException(status_code=400, detail=f"Unknown webshell type: {ws_type}. Available: {', '.join(WEBSHELL_DECRYPT_RULES.keys())}")

        ws_info = {"type": ws_type, "type_name": rule["name"], "key": ws_key}
        result = decrypt_transaction(tx, ws_info)
        return {
            "transaction_id": tx_id,
            "mode": "manual",
            "type": ws_type,
            "type_name": rule["name"],
            "key": ws_key,
            "results": result.get("results", []),
        }
