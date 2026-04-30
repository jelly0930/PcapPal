"""Webshell payload decryptor - rule engine for common webshell families."""
import re
import base64
import hashlib
import urllib.parse
import zlib
import gzip
import struct
from typing import Dict, Any, Optional, Callable, List

# Optional AES/DES/RC4 support
try:
    from Crypto.Cipher import AES, DES, DES3, ARC4
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


def _safe_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if 1 <= pad_len <= 16 and data.endswith(bytes([pad_len]) * pad_len):
        return data[:-pad_len]
    return data


def _try_decode(data: bytes, encodings=("utf-8", "gbk", "gb2312", "latin-1")) -> str:
    for enc in encodings:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="ignore")


def _is_reasonable_text(text: str, min_printable_ratio: float = 0.6) -> bool:
    if not text or len(text) < 2:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    ratio = printable / len(text)
    return ratio >= min_printable_ratio


def _safe_b64decode(s: str) -> bytes:
    """Base64 decode with auto-padding."""
    s = s.strip()
    # 补齐 padding
    if len(s) % 4 != 0:
        s += "=" * (4 - len(s) % 4)
    return base64.b64decode(s)


def _to_bytes(payload: str) -> bytes:
    """Try to convert payload string to raw bytes (base64 or hex)."""
    try:
        return _safe_b64decode(payload)
    except Exception:
        pass
    try:
        return bytes.fromhex(payload)
    except Exception:
        pass
    return payload.encode("latin-1", errors="ignore")


def _try_gzip_decompress(data: bytes) -> bytes:
    """Try zlib/gzip/raw-deflate decompress. Returns original if all fail."""
    for decompress_fn in [
        lambda d: zlib.decompress(d),
        lambda d: zlib.decompress(d, 16 + zlib.MAX_WBITS),  # gzip
        lambda d: zlib.decompress(d, -zlib.MAX_WBITS),       # raw deflate
    ]:
        try:
            return decompress_fn(data)
        except Exception:
            continue
    return data


def _decode_with_auto_gzip(data: bytes) -> str:
    """Decode bytes to string, auto-trying gzip/zlib decompress first."""
    # First try direct decode
    text = _try_decode(data)
    if _is_reasonable_text(text):
        return text
    # Try decompress then decode
    decompressed = _try_gzip_decompress(data)
    if decompressed is not data:
        text = _try_decode(decompressed)
        if _is_reasonable_text(text, 0.5):
            return "[gzip decompressed]\n" + text
    # Return raw hex if nothing worked
    return text


# ============================================================================
# Decryptors — each returns a string (decrypted result or error message)
# Decryptors ending with _bytes return raw bytes for chaining.
# ============================================================================

def _decrypt_behinder_bytes(payload: str, key: str) -> bytes:
    """Behinder (冰蝎) core: Base64→AES-CBC decrypt. Returns raw bytes."""
    if not _HAS_CRYPTO:
        raise RuntimeError("pycryptodome required")
    if not key:
        raise ValueError("Key required")
    raw = base64.b64decode(payload)
    aes_key = hashlib.md5(key.encode("utf-8")).digest()
    iv = aes_key[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    return _safe_unpad(cipher.decrypt(raw))


def decrypt_behinder_req(payload: str, key: str) -> str:
    """Behinder request: AES-CBC decrypt → auto gzip."""
    try:
        raw = _decrypt_behinder_bytes(payload, key)
        return _decode_with_auto_gzip(raw)
    except Exception as e:
        return f"[Behinder req decrypt failed: {e}]"


def decrypt_behinder_resp(payload: str, key: str) -> str:
    """Behinder response: AES-CBC decrypt → auto gzip (response is often gzipped)."""
    try:
        raw = _decrypt_behinder_bytes(payload, key)
        return _decode_with_auto_gzip(raw)
    except Exception as e:
        return f"[Behinder resp decrypt failed: {e}]"


def _godzilla_aes_ecb_decrypt(data: bytes, aes_key: bytes) -> bytes:
    """Godzilla core: AES-ECB decrypt + unpad."""
    if not _HAS_CRYPTO:
        raise RuntimeError("pycryptodome required")
    cipher = AES.new(aes_key, AES.MODE_ECB)
    return _safe_unpad(cipher.decrypt(data))


def _godzilla_aes_ecb_encrypt(data: bytes, aes_key: bytes) -> bytes:
    """AES-ECB encrypt + PKCS7 pad."""
    if not _HAS_CRYPTO:
        raise RuntimeError("pycryptodome required")
    length = 16 - (len(data) % 16)
    padded = data + bytes([length]) * length
    cipher = AES.new(aes_key, AES.MODE_ECB)
    return cipher.encrypt(padded)


def _godzilla_md5_tag(pwd: str, key: str) -> str:
    """Compute Godzilla MD5 verification tag: MD5(pwd + key).upper()"""
    return hashlib.md5((pwd + key).encode("utf-8")).hexdigest().upper()


def _godzilla_parse_kv(data: bytes) -> str:
    """Parse Godzilla binary KV format (0x02 separated) into readable text."""
    result_parts = []
    i = 0
    while i < len(data):
        if data[i] != 0x02:
            i += 1
            continue
        i += 1
        key_start = i
        while i < len(data) and data[i] != 0x02:
            i += 1
        if i >= len(data):
            break
        k = data[key_start:i].decode("utf-8", errors="replace")
        i += 1
        if i + 4 > len(data):
            break
        length = struct.unpack('<I', data[i:i + 4])[0]
        i += 4
        if i + length > len(data):
            # Try to show what we can
            v = data[i:]
            result_parts.append(f"{k} = {v.decode('utf-8', errors='replace')}")
            break
        v = data[i:i + length]
        i += length
        try:
            val_str = v.decode("utf-8")
        except UnicodeDecodeError:
            val_str = f"(binary, {len(v)} bytes) {v[:64].hex()}"
        result_parts.append(f"{k} = {val_str}")
    if result_parts:
        return "\n".join(result_parts)
    return data.decode("utf-8", errors="replace")


def _godzilla_strip_md5_wrapper(response_str: str, pwd: str = "", key: str = "") -> str:
    """Strip Godzilla MD5 wrapper from response: MD5[:16] + base64_data + MD5[16:]"""
    s = response_str.strip()
    if len(s) < 32:
        return s
    # Try to strip: first 16 chars + last 16 chars are MD5
    prefix = s[:16]
    suffix = s[-16:]
    middle = s[16:-16]
    # Verify it looks like base64 data in the middle
    if re.match(r'^[A-Za-z0-9+/=]+$', middle) and len(middle) >= 4:
        # Optionally verify MD5 tag if pwd and key are known
        if pwd and key:
            expected = _godzilla_md5_tag(pwd, key)
            if prefix == expected[:16] and suffix == expected[16:]:
                pass  # Verified
            else:
                # Not matching, but still try stripping — could be different variant
                pass
        return middle
    # Doesn't look like MD5 wrapper, return as-is
    return s


def _godzilla_get_aes_keys(key: str, pass_: str = "") -> List[tuple]:
    """Get candidate (aes_key_bytes, label) for Godzilla.
    Tries multiple derivations: direct key, MD5(key), MD5(pass)."""
    candidates = []
    # 1. Direct key (most common: 16-char hex string like "3c6e0b8a9c15224a")
    if key:
        key_bytes = key.encode("utf-8")
        # Pad/truncate to valid AES size
        for ksz in (16, 24, 32):
            if len(key_bytes) == ksz:
                candidates.append((key_bytes, f"direct key ({ksz}B)"))
                break
        if len(key_bytes) < 16:
            candidates.append((key_bytes.ljust(16, b'\0'), "direct key (padded)"))
        # 2. MD5(key)[:16] — some Godzilla variants
        md5_key = hashlib.md5(key_bytes).digest()[:16]
        candidates.append((md5_key, "MD5(key)[:16]"))
        # 3. key as hex bytes (if key is a hex string like "3c6e0b8a9c15224a")
        try:
            hex_bytes = bytes.fromhex(key)
            if len(hex_bytes) in (16, 24, 32) and hex_bytes != key_bytes:
                candidates.append((hex_bytes, "key as hex bytes"))
        except ValueError:
            pass
    if pass_:
        # 4. MD5(pass)[:16]
        md5_pass = hashlib.md5(pass_.encode("utf-8")).digest()[:16]
        candidates.append((md5_pass, "MD5(pass)[:16]"))
        # 5. pass.encode() directly if 16 bytes
        pass_bytes = pass_.encode("utf-8")
        if len(pass_bytes) == 16:
            candidates.append((pass_bytes, "direct pass (16B)"))
    return candidates


def decrypt_godzilla_req(payload: str, key: str, pass_: str = "") -> str:
    """Godzilla request: Base64 → AES-ECB decrypt → GZIP decompress → KV parse.

    Key derivation: tries direct key, MD5(key), MD5(pass).
    AES mode: ECB (standard Godzilla).
    """
    if not _HAS_CRYPTO:
        return "[pycryptodome required for Godzilla decryption]"
    if not key and not pass_:
        return "[Key or pass required for Godzilla decryption]"
    try:
        raw = _safe_b64decode(payload)
    except Exception as e:
        return f"[Base64 decode failed: {e}]"

    candidates = _godzilla_get_aes_keys(key, pass_)
    errors = []
    for aes_key, label in candidates:
        try:
            decrypted = _godzilla_aes_ecb_decrypt(raw, aes_key)
            # Try gzip + KV parse
            try:
                decompressed = gzip.decompress(decrypted)
                kv_text = _godzilla_parse_kv(decompressed)
                return f"[{label}, AES-ECB, gzip]\n{kv_text}"
            except Exception:
                pass
            # Try raw deflate
            try:
                decompressed = zlib.decompress(decrypted, -zlib.MAX_WBITS)
                kv_text = _godzilla_parse_kv(decompressed)
                return f"[{label}, AES-ECB, raw-deflate]\n{kv_text}"
            except Exception:
                pass
            # Try without decompress — maybe it's raw text
            text = _try_decode(decrypted)
            if _is_reasonable_text(text, 0.5):
                return f"[{label}, AES-ECB, no-gzip]\n{text}"
            errors.append(f"{label}: decrypt ok but data not readable (hex: {decrypted[:32].hex()})")
        except Exception as e:
            errors.append(f"{label}: {e}")
    return f"[Godzilla req decrypt failed. Tried {len(candidates)} keys.]\n" + "\n".join(errors[:5])


def decrypt_godzilla_resp(payload: str, key: str, pass_: str = "") -> str:
    """Godzilla response: strip MD5 wrapper → Base64 → AES-ECB → GZIP decompress.

    Response format: MD5(pwd+key)[:16] + base64(AES_ECB(gzip(result))) + MD5(pwd+key)[16:]
    """
    if not _HAS_CRYPTO:
        return "[pycryptodome required for Godzilla decryption]"
    if not key and not pass_:
        return "[Key or pass required for Godzilla decryption]"

    # Strip MD5 wrapper if present
    b64_data = _godzilla_strip_md5_wrapper(payload, pass_, key)
    try:
        raw = _safe_b64decode(b64_data)
    except Exception as e:
        return f"[Base64 decode failed (after MD5 strip): {e}]"

    candidates = _godzilla_get_aes_keys(key, pass_)
    errors = []
    for aes_key, label in candidates:
        try:
            decrypted = _godzilla_aes_ecb_decrypt(raw, aes_key)
            # Try gzip
            try:
                decompressed = gzip.decompress(decrypted)
                text = _try_decode(decompressed)
                return f"[{label}, AES-ECB, gzip]\n{text}"
            except Exception:
                pass
            # Try raw deflate
            try:
                decompressed = zlib.decompress(decrypted, -zlib.MAX_WBITS)
                text = _try_decode(decompressed)
                return f"[{label}, AES-ECB, raw-deflate]\n{text}"
            except Exception:
                pass
            # Try zlib
            try:
                decompressed = zlib.decompress(decrypted)
                text = _try_decode(decompressed)
                return f"[{label}, AES-ECB, zlib]\n{text}"
            except Exception:
                pass
            # Try without decompress
            text = _try_decode(decrypted)
            if _is_reasonable_text(text, 0.5):
                return f"[{label}, AES-ECB, no-gzip]\n{text}"
            errors.append(f"{label}: decrypt ok but data not readable (hex: {decrypted[:32].hex()})")
        except Exception as e:
            errors.append(f"{label}: {e}")
    return f"[Godzilla resp decrypt failed. Tried {len(candidates)} keys.]\n" + "\n".join(errors[:5])


def _extract_godzilla_pass(req_body: str) -> str:
    """Extract pass= parameter name from Godzilla request body.
    In Godzilla, pass is the parameter name that carries encrypted data, e.g., 'pass1024'.
    """
    # Look for patterns like pass=somevalue where value is base64
    m = re.search(r'(?:^|&)([a-zA-Z0-9_]+)=([A-Za-z0-9+/=]{20,})', req_body)
    if m:
        return m.group(1)
    return ""


def decrypt_asp_bypass(payload: str, key: str) -> str:
    try:
        raw = base64.b64decode(payload)
    except Exception as e:
        return f"[Base64 decode failed: {e}]"
    if not key:
        return "[Key required for ASP XOR decryption]"
    key_bytes = key.encode("latin-1")
    result = bytes([raw[i] ^ key_bytes[(i + 1) % len(key_bytes)] for i in range(len(raw))])
    return _try_decode(result)


def decrypt_aes_ecb(payload: str, key: str) -> str:
    if not _HAS_CRYPTO:
        return "[pycryptodome required for AES decryption]"
    if not key:
        return "[Key required for AES decryption]"
    try:
        raw = base64.b64decode(payload)
    except Exception:
        try:
            raw = bytes.fromhex(payload)
        except Exception as e:
            return f"[Cannot decode payload: {e}]"
    key_bytes = key.encode("utf-8")
    for ksz in (32, 24, 16):
        if len(key_bytes) >= ksz:
            key_bytes = key_bytes[:ksz]
            break
    else:
        key_bytes = key_bytes.ljust(16, b'\0')
    try:
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted = _safe_unpad(cipher.decrypt(raw))
        return _decode_with_auto_gzip(decrypted)
    except Exception as e:
        return f"[AES-ECB decrypt failed: {e}]"


def decrypt_aes_cbc(payload: str, key: str, iv: str = "") -> str:
    if not _HAS_CRYPTO:
        return "[pycryptodome required for AES decryption]"
    if not key:
        return "[Key required for AES-CBC decryption]"
    try:
        raw = base64.b64decode(payload)
    except Exception:
        try:
            raw = bytes.fromhex(payload)
        except Exception as e:
            return f"[Cannot decode payload: {e}]"
    key_bytes = key.encode("utf-8")
    for ksz in (32, 24, 16):
        if len(key_bytes) >= ksz:
            key_bytes = key_bytes[:ksz]
            break
    else:
        key_bytes = key_bytes.ljust(16, b'\0')
    if iv:
        iv_bytes = iv.encode("utf-8")[:16].ljust(16, b'\0')
    else:
        iv_bytes = hashlib.md5(key_bytes).digest()[:16]
    try:
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
        decrypted = _safe_unpad(cipher.decrypt(raw))
        return _decode_with_auto_gzip(decrypted)
    except Exception as e:
        return f"[AES-CBC decrypt failed: {e}]"


def decrypt_des_ecb(payload: str, key: str) -> str:
    if not _HAS_CRYPTO:
        return "[pycryptodome required for DES decryption]"
    if not key:
        return "[Key required for DES decryption]"
    try:
        raw = base64.b64decode(payload)
    except Exception:
        try:
            raw = bytes.fromhex(payload)
        except Exception as e:
            return f"[Cannot decode payload: {e}]"
    key_bytes = key.encode("utf-8")[:8].ljust(8, b'\0')
    try:
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        decrypted = _safe_unpad(cipher.decrypt(raw))
        return _try_decode(decrypted)
    except Exception as e:
        return f"[DES-ECB decrypt failed: {e}]"


def decrypt_3des_ecb(payload: str, key: str) -> str:
    if not _HAS_CRYPTO:
        return "[pycryptodome required for 3DES decryption]"
    if not key:
        return "[Key required for 3DES decryption]"
    try:
        raw = base64.b64decode(payload)
    except Exception:
        try:
            raw = bytes.fromhex(payload)
        except Exception as e:
            return f"[Cannot decode payload: {e}]"
    key_bytes = key.encode("utf-8")[:24].ljust(24, b'\0')
    try:
        cipher = DES3.new(key_bytes, DES3.MODE_ECB)
        decrypted = _safe_unpad(cipher.decrypt(raw))
        return _try_decode(decrypted)
    except Exception as e:
        return f"[3DES-ECB decrypt failed: {e}]"


def decrypt_rc4(payload: str, key: str) -> str:
    if not _HAS_CRYPTO:
        return "[pycryptodome required for RC4 decryption]"
    if not key:
        return "[Key required for RC4 decryption]"
    try:
        raw = base64.b64decode(payload)
    except Exception:
        try:
            raw = bytes.fromhex(payload)
        except Exception as e:
            return f"[Cannot decode payload: {e}]"
    try:
        cipher = ARC4.new(key.encode("utf-8"))
        decrypted = cipher.decrypt(raw)
        return _decode_with_auto_gzip(decrypted)
    except Exception as e:
        return f"[RC4 decrypt failed: {e}]"


def decrypt_xor(payload: str, key: str) -> str:
    if not key:
        return "[Key required for XOR decryption]"
    raw = _to_bytes(payload)
    key_bytes = key.encode("latin-1", errors="ignore")
    result = bytes([raw[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(raw))])
    text = _try_decode(result)
    if _is_reasonable_text(text):
        return text
    return f"[XOR did not yield readable text]\n\nRaw hex:\n{result[:200].hex()}"


def decrypt_xor_single(payload: str, key: str) -> str:
    raw = _to_bytes(payload)
    if key:
        try:
            k = int(key, 0)
            if 0 <= k <= 255:
                result = bytes([b ^ k for b in raw])
                return _try_decode(result)
        except ValueError:
            pass
        return "[Key must be a decimal number 0-255 for single-byte XOR]"
    best, best_score = "", 0
    for k in range(256):
        result = bytes([b ^ k for b in raw])
        text = _try_decode(result)
        score = sum(1 for c in text if c.isprintable() or c in " \r\n\t")
        if score > best_score and _is_reasonable_text(text):
            best_score = score
            best = f"[XOR key=0x{k:02x} ({k})]\n{text}"
    return best or "[Could not auto-detect XOR key]"


def decrypt_jspx_aes(payload: str, key: str) -> str:
    if not _HAS_CRYPTO:
        return "[pycryptodome required for AES decryption]"
    if not key:
        return "[Key required for JSPX AES decryption]"
    try:
        raw = base64.b64decode(payload)
        cipher = AES.new(key.encode("utf-8"), AES.MODE_ECB)
        decrypted = _safe_unpad(cipher.decrypt(raw))
        return _try_decode(decrypted)
    except Exception as e:
        return f"[AES decrypt failed: {e}]"


def decrypt_jspx_eval(payload: str, _key: str = "") -> str:
    try:
        s = urllib.parse.unquote(payload)
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
        return s[:2000]
    except Exception as e:
        return f"[JSPX eval decode failed: {e}]"


def decrypt_php_eval_base64(payload: str, _key: str = "") -> str:
    try:
        m = re.search(r"urldecode\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", payload)
        inner = m.group(1) if m else payload
        s = urllib.parse.unquote(inner)
        if "%" in s:
            s = urllib.parse.unquote(s)
        candidates = []
        if s.startswith("="):
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


def decrypt_base64(payload: str, _key: str = "") -> str:
    try:
        for pad in ["", "=", "=="]:
            try:
                decoded = base64.b64decode(payload + pad)
                return _try_decode(decoded)
            except Exception:
                continue
        return "[Could not base64 decode]"
    except Exception as e:
        return f"[Base64 decode failed: {e}]"


def decrypt_hex(payload: str, _key: str = "") -> str:
    try:
        decoded = bytes.fromhex(payload.replace(" ", "").replace("\\x", ""))
        return _try_decode(decoded)
    except Exception as e:
        return f"[Hex decode failed: {e}]"


def decrypt_urldecode(payload: str, _key: str = "") -> str:
    try:
        s = payload
        for _ in range(5):
            decoded = urllib.parse.unquote(s)
            if decoded == s:
                break
            s = decoded
        return s
    except Exception as e:
        return f"[URL decode failed: {e}]"


def decrypt_rot13(payload: str, _key: str = "") -> str:
    import codecs
    try:
        return codecs.decode(payload, "rot_13")
    except Exception as e:
        return f"[ROT13 decode failed: {e}]"


def decrypt_reverse(payload: str, _key: str = "") -> str:
    rev = payload[::-1]
    try:
        for pad in ["", "=", "=="]:
            try:
                decoded = base64.b64decode(rev + pad)
                text = _try_decode(decoded)
                if _is_reasonable_text(text) and len(text) > 5:
                    return f"[Reversed + Base64]\n{text}"
            except Exception:
                continue
    except Exception:
        pass
    return f"[Reversed (raw)]\n{rev[:2000]}"


def decrypt_zlib(payload: str, _key: str = "") -> str:
    raw = _to_bytes(payload)
    for decompress_fn in [zlib.decompress, lambda d: zlib.decompress(d, 16 + zlib.MAX_WBITS)]:
        try:
            result = decompress_fn(raw)
            return _try_decode(result)
        except Exception:
            continue
    return "[Zlib/gzip decompression failed]"


def decrypt_php_xor(payload: str, key: str) -> str:
    try:
        raw = base64.b64decode(payload)
    except Exception:
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
    best, best_score = "", 0
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
    return best or "[Could not auto-detect XOR key]"


def decrypt_generic(payload: str, key: str = "") -> str:
    results = []
    try:
        raw = base64.b64decode(payload)
        text = _try_decode(raw)
        if _is_reasonable_text(text) and len(text) > 5:
            results.append(("base64", text))
    except Exception:
        pass
    try:
        raw = bytes.fromhex(payload)
        text = _try_decode(raw)
        if _is_reasonable_text(text) and len(text) > 5:
            results.append(("hex", text))
    except Exception:
        pass
    if key:
        raw = _to_bytes(payload)
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

# Each rule can define:
#   decrypt_req: function(req_payload, key, ...) → str   (request body decryption)
#   decrypt_resp: function(resp_payload, key, ...) → str  (response body decryption)
#   decrypt: legacy shortcut — if only decrypt is set, used for both req & resp

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
        "needs_key": True,
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
        "description": "AES/ECB/PKCS5Padding",
        "needs_key": True,
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
        "needs_key": False,
    },
    "behinder": {
        "name": "冰蝎 (Behinder)",
        "detect_patterns": [
            r'behinder',
            # 冰蝎请求特征：单个大体积 base64 参数 POST 到动态脚本
            r'(?:^|&)=[A-Za-z0-9+/=]{100,}(?:&|$)',
            # 冰蝎响应特征：纯 base64 且长度 > 80（加密后的响应体）
            r'^[A-Za-z0-9+/=]{80,}$',
        ],
        "key_patterns": [
            r'key\s*=\s*["\']([^"\']{4,})["\']',
            r'password\s*=\s*["\']([^"\']{4,})["\']',
            r'pwd\s*=\s*["\']([^"\']{4,})["\']',
        ],
        "decrypt_req": decrypt_behinder_req,
        "decrypt_resp": decrypt_behinder_resp,
        "description": "AES-CBC, key=MD5(password), IV=key[:16], auto gzip, 填密码",
        "needs_key": True,
    },
    "godzilla": {
        "name": "哥斯拉 (Godzilla)",
        "detect_patterns": [
            r'godzilla',
            r'pass=[a-zA-Z0-9]+&class=',
            # Godzilla 请求特征：class= 参数 + base64 值
            r'class\s*=\s*[a-zA-Z]+&',
            # Godzilla 响应特征：MD5 包裹（16位hex + base64 + 16位hex）
            r'^[A-Fa-f0-9]{16}[A-Za-z0-9+/=]{20,}[A-Fa-f0-9]{16}$',
        ],
        "key_patterns": [
            r'pass\s*=\s*["\']?([a-zA-Z0-9]{8,})["\']?',
            r'key\s*=\s*["\']([a-f0-9]{16})["\']',
        ],
        "decrypt_req": decrypt_godzilla_req,
        "decrypt_resp": decrypt_godzilla_resp,
        "description": "AES-ECB, key=密钥字符串(16B), 响应MD5包裹, auto gzip, pass=参数名",
        "needs_key": True,
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
        "needs_key": False,
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
        "needs_key": False,
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
        "needs_key": False,
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
        "needs_key": True,
    },
    # --- Generic crypto primitives (manual only) ---
    "aes_ecb": {
        "name": "AES-ECB",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_aes_ecb,
        "description": "AES/ECB decrypt, auto gzip, key padded to 16/24/32",
        "needs_key": True,
        "manual_only": True,
    },
    "aes_cbc": {
        "name": "AES-CBC",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_aes_cbc,
        "description": "AES/CBC decrypt, auto gzip, key + optional IV",
        "needs_key": True,
        "needs_iv": True,
        "manual_only": True,
    },
    "des_ecb": {
        "name": "DES-ECB",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_des_ecb,
        "description": "DES/ECB decrypt (8-byte key)",
        "needs_key": True,
        "manual_only": True,
    },
    "3des_ecb": {
        "name": "3DES-ECB",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_3des_ecb,
        "description": "3DES/ECB decrypt (24-byte key)",
        "needs_key": True,
        "manual_only": True,
    },
    "rc4": {
        "name": "RC4",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_rc4,
        "description": "RC4 stream cipher, auto gzip",
        "needs_key": True,
        "manual_only": True,
    },
    "xor": {
        "name": "XOR",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_xor,
        "description": "XOR with repeating key",
        "needs_key": True,
        "manual_only": True,
    },
    "xor_single": {
        "name": "XOR 单字节",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_xor_single,
        "description": "Single-byte XOR (key 0-255, or auto brute-force)",
        "needs_key": False,
        "manual_only": True,
    },
    "base64": {
        "name": "Base64",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_base64,
        "description": "Raw Base64 decode",
        "needs_key": False,
        "manual_only": True,
    },
    "hex": {
        "name": "Hex",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_hex,
        "description": "Hex decode",
        "needs_key": False,
        "manual_only": True,
    },
    "urldecode": {
        "name": "URL Decode",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_urldecode,
        "description": "URL decode (multiple passes)",
        "needs_key": False,
        "manual_only": True,
    },
    "rot13": {
        "name": "ROT13",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_rot13,
        "description": "ROT13 substitution",
        "needs_key": False,
        "manual_only": True,
    },
    "reverse": {
        "name": "Reverse+Base64",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_reverse,
        "description": "Reverse string, then try Base64 decode",
        "needs_key": False,
        "manual_only": True,
    },
    "zlib": {
        "name": "Zlib/Gzip",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_zlib,
        "description": "Zlib/gzip decompress",
        "needs_key": False,
        "manual_only": True,
    },
    "generic": {
        "name": "Generic",
        "detect_patterns": [],
        "key_patterns": [],
        "decrypt": decrypt_generic,
        "description": "Try base64, hex, XOR automatically",
        "needs_key": False,
    },
}


def detect_webshell_type(body: str, is_request: bool = False) -> Optional[str]:
    """返回第一个匹配的 webshell 类型（向后兼容）。"""
    types = detect_webshell_types(body, is_request)
    return types[0] if types else None


def detect_webshell_types(body: str, is_request: bool = False) -> List[str]:
    """返回所有匹配的 webshell 类型列表。"""
    matches = []
    for rule_id, rule in WEBSHELL_DECRYPT_RULES.items():
        if rule_id in ("generic",) or rule.get("manual_only"):
            continue
        for pat in rule["detect_patterns"]:
            if re.search(pat, body, re.IGNORECASE):
                matches.append(rule_id)
                break
    return matches


def extract_key(body: str, rule_id: str) -> Optional[str]:
    rule = WEBSHELL_DECRYPT_RULES.get(rule_id)
    if not rule:
        return None
    for pat in rule.get("key_patterns", []):
        m = re.search(pat, body)
        if m:
            return m.group(1)
    return None


def _extract_param_value(body: str, param_name: str) -> Optional[str]:
    m = re.search(rf'(?:^|&){re.escape(param_name)}=([^&\s]+)', body)
    if m:
        return urllib.parse.unquote(m.group(1))
    return None


def _find_base64_params(body: str) -> List[tuple]:
    results = []
    for m in re.finditer(r'([a-zA-Z0-9_]+)=([A-Za-z0-9+/=%]+)', body):
        name, val = m.group(1), urllib.parse.unquote(m.group(2))
        if len(val) >= 20 and re.match(r'^[A-Za-z0-9+/=]+$', val):
            results.append((name, val))
    return results


def _find_all_params(body: str) -> List[tuple]:
    results = []
    for m in re.finditer(r'([a-zA-Z0-9_]+)=([^&\s]*)', body):
        name, val = m.group(1), urllib.parse.unquote(m.group(2))
        if len(val) >= 8:
            results.append((name, val))
    return results


def _get_decrypt_fn(rule: Dict, direction: str) -> Optional[Callable]:
    """Get the appropriate decrypt function for request or response."""
    if direction == "response" and rule.get("decrypt_resp"):
        return rule["decrypt_resp"]
    if direction == "request" and rule.get("decrypt_req"):
        return rule["decrypt_req"]
    return rule.get("decrypt")


def _apply_decrypt(decrypt_fn: Callable, payload: str, key: str, iv: str = "", pass_: str = "") -> str:
    """Apply a decrypt function with appropriate arguments based on its signature."""
    import inspect
    sig = inspect.signature(decrypt_fn)
    params = list(sig.parameters.keys())
    # Godzilla fns accept pass_
    if "pass_" in params:
        return decrypt_fn(payload, key, pass_)
    if "iv" in params:
        return decrypt_fn(payload, key, iv)
    if key or len(params) >= 2:
        try:
            return decrypt_fn(payload, key)
        except TypeError:
            return decrypt_fn(payload)
    return decrypt_fn(payload)


def analyze_transaction(tx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    resp_body = tx.get("responseBody", "") or ""
    req_body = tx.get("requestBody", "") or ""
    uri = tx.get("uri", "") or ""
    req_body_decoded = urllib.parse.unquote(req_body)

    # 收集所有匹配的类型（响应、请求、解码后请求）
    all_types = []
    resp_types = detect_webshell_types(resp_body, is_request=False)
    req_types = detect_webshell_types(req_body, is_request=True)
    decoded_types = detect_webshell_types(req_body_decoded, is_request=True)
    # 保持顺序：响应优先，去重
    for t in resp_types + req_types + decoded_types:
        if t not in all_types:
            all_types.append(t)

    # 兜底：动态脚本 URL + base64 参数
    if not all_types and uri:
        if re.search(r'\.(asp|jsp|jspx|php)\b', uri, re.I):
            b64_params = _find_base64_params(req_body)
            if b64_params:
                all_types.append("unknown_base64")

    if not all_types:
        return None

    # 取第一个匹配类型（用于快速返回；多类型尝试在 decrypt_transaction 层面处理）
    ws_type = all_types[0]
    source = "response" if ws_type in resp_types else "request"

    key = ""
    if ws_type in WEBSHELL_DECRYPT_RULES:
        key = extract_key(resp_body, ws_type) or extract_key(req_body, ws_type) or extract_key(req_body_decoded, ws_type) or ""

    return {
        "type": ws_type,
        "type_name": WEBSHELL_DECRYPT_RULES.get(ws_type, {}).get("name", ws_type),
        "key": key,
        "description": WEBSHELL_DECRYPT_RULES.get(ws_type, {}).get("description", ""),
        "source": source,
        "all_types": all_types,  # 保留所有匹配类型，供解密时回退
    }


def decrypt_transaction(tx: Dict[str, Any], ws_info: Dict[str, Any]) -> Dict[str, Any]:
    """Decrypt both request and response bodies of a transaction.

    Returns a dict with separate 'request_results' and 'response_results' lists,
    plus a flat 'results' list for backward compatibility.
    """
    rule_id = ws_info["type"]
    key = ws_info.get("key", "")
    iv = ws_info.get("iv", "")
    param_name = ws_info.get("param", "")
    pass_ = ws_info.get("pass", "")

    req_body = tx.get("requestBody", "") or ""
    resp_body = tx.get("responseBody", "") or ""
    uri = tx.get("uri", "") or ""
    method = tx.get("method", "") or ""

    rule = WEBSHELL_DECRYPT_RULES.get(rule_id)
    if not rule:
        return {"transaction_id": tx.get("id"), "uri": uri, "method": method,
                "type": rule_id, "type_name": ws_info.get("type_name", rule_id),
                "key": key, "request_results": [], "response_results": [], "results": []}

    # Extract pass= for Godzilla
    if rule_id == "godzilla" and not pass_:
        pass_ = _extract_godzilla_pass(req_body)

    request_results: List[Dict[str, str]] = []
    response_results: List[Dict[str, str]] = []

    # --- DECRYPT REQUEST ---
    req_fn = _get_decrypt_fn(rule, "request")
    if req_fn and req_body:
        if rule.get("manual_only"):
            # Manual-only: extract param(s) and apply
            if param_name:
                payload = _extract_param_value(req_body, param_name)
                if payload and len(payload) >= 8:
                    try:
                        decrypted = _apply_decrypt(req_fn, payload, key, iv, pass_)
                    except Exception as e:
                        decrypted = f"[Error: {e}]"
                    request_results.append({"param": param_name, "original": payload[:200],
                        "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
            else:
                for pname, payload in _find_base64_params(req_body) or _find_all_params(req_body):
                    if len(payload) < 8:
                        continue
                    try:
                        decrypted = _apply_decrypt(req_fn, payload, key, iv, pass_)
                    except Exception as e:
                        decrypted = f"[Error: {e}]"
                    request_results.append({"param": pname, "original": payload[:200],
                        "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
        elif rule_id == "asp_bypass":
            for pname in ["plryormg41", "content", "payload", "data"]:
                payload = _extract_param_value(req_body, pname)
                if payload and len(payload) >= 20:
                    decrypted = decrypt_asp_bypass(payload, key)
                    request_results.append({"param": pname, "original": payload[:200],
                        "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
                    break
            if not request_results:
                for pname, payload in _find_base64_params(req_body):
                    if len(payload) >= 20:
                        decrypted = decrypt_asp_bypass(payload, key)
                        request_results.append({"param": pname, "original": payload[:200],
                            "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
        elif rule_id in ("jspx_aes",):
            for pname in ["vhdb1uiipf", "pass", "payload", "data", "cmd"]:
                payload = _extract_param_value(req_body, pname)
                if payload and len(payload) >= 20:
                    decrypted = decrypt_jspx_aes(payload, key)
                    request_results.append({"param": pname, "original": payload[:200],
                        "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
                    break
            if not request_results:
                for pname, payload in _find_base64_params(req_body):
                    if len(payload) >= 20:
                        decrypted = decrypt_jspx_aes(payload, key)
                        request_results.append({"param": pname, "original": payload[:200],
                            "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
        elif rule_id == "jspx_eval":
            for pname in ["vhdb1uiipf", "pass", "payload", "data", "cmd"]:
                payload = _extract_param_value(req_body, pname)
                if payload and len(payload) >= 20:
                    decrypted = decrypt_jspx_eval(payload, key)
                    request_results.append({"param": pname, "original": payload[:200],
                        "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
                    break
            if not request_results:
                for pname, payload in _find_all_params(req_body):
                    if len(payload) >= 20:
                        decrypted = decrypt_jspx_eval(payload, key)
                        request_results.append({"param": pname, "original": payload[:200],
                            "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
        elif rule_id in ("behinder", "godzilla"):
            # 优先用用户指定的 pass 参数名，再自动推断，最后通用列表
            param_names = []
            if pass_:
                param_names.append(pass_)
            if rule_id == "godzilla":
                auto_pass = _extract_godzilla_pass(req_body)
                if auto_pass and auto_pass not in param_names:
                    param_names.append(auto_pass)
            for pname in ["pass", "payload", "data", "cmd", "c", "vhdb1uiipf"]:
                if pname not in param_names:
                    param_names.append(pname)
            for pname in param_names:
                payload = _extract_param_value(req_body, pname)
                if payload and len(payload) >= 20:
                    decrypted = _apply_decrypt(req_fn, payload, key, iv, pass_)
                    request_results.append({"param": pname, "original": payload[:200],
                        "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
                    break
            if not request_results:
                for pname, payload in _find_base64_params(req_body):
                    if len(payload) >= 20:
                        decrypted = _apply_decrypt(req_fn, payload, key, iv, pass_)
                        request_results.append({"param": pname, "original": payload[:200],
                            "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
        elif rule_id in ("php_eval_base64", "php_simple_eval"):
            m = re.search(
                r"([a-zA-Z0-9_]+)=(eval%28base64_decode%28strrev%28urldecode%28%27[^%]+%27%29%29%29%29",
                req_body,
            )
            if m:
                payload = urllib.parse.unquote(m.group(2))
                decrypted = decrypt_php_eval_base64(payload)
                request_results.append({"param": m.group(1), "original": payload[:200],
                    "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
            if not request_results:
                for pname, payload in _find_base64_params(req_body):
                    if len(payload) >= 20:
                        decrypted = decrypt_php_eval_base64(payload)
                        if decrypted and not decrypted.startswith("["):
                            request_results.append({"param": pname, "original": payload[:200],
                                "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
        elif rule_id == "php_simple_base64":
            for pname, payload in _find_base64_params(req_body):
                if len(payload) >= 20:
                    decrypted = decrypt_php_simple_base64(payload)
                    if decrypted and not decrypted.startswith("["):
                        request_results.append({"param": pname, "original": payload[:200],
                            "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
        elif rule_id == "php_xor":
            for pname, payload in _find_base64_params(req_body):
                if len(payload) >= 20:
                    decrypted = decrypt_php_xor(payload, key)
                    request_results.append({"param": pname, "original": payload[:200],
                        "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
        elif rule_id == "unknown_base64":
            for pname, payload in _find_base64_params(req_body):
                if len(payload) >= 20:
                    for rid, r in WEBSHELL_DECRYPT_RULES.items():
                        if rid in ("generic", "unknown_base64") or r.get("manual_only"):
                            continue
                        fn = _get_decrypt_fn(r, "request")
                        if fn:
                            decrypted = _apply_decrypt(fn, payload, key, iv, pass_)
                        else:
                            decrypted = "[no decrypt fn]"
                        is_err = decrypted.startswith("[") and "\n" not in decrypted and len(decrypted) < 80
                        if decrypted and not is_err and len(decrypted) > 5:
                            request_results.append({"param": pname, "original": payload[:200],
                                "original_len": len(payload), "decrypted": decrypted,
                                "decrypted_len": len(decrypted), "matched_rule": rid})
                            break
                    else:
                        decrypted = decrypt_generic(payload, key)
                        if decrypted and not decrypted.startswith("["):
                            request_results.append({"param": pname, "original": payload[:200],
                                "original_len": len(payload), "decrypted": decrypted,
                                "decrypted_len": len(decrypted), "matched_rule": "generic"})

    # --- DECRYPT RESPONSE ---
    resp_fn = _get_decrypt_fn(rule, "response")
    if resp_fn and resp_body:
        # For webshell types, response body is often one big encrypted blob
        resp_decoded = urllib.parse.unquote(resp_body)
        # Try the full body as payload
        payload = resp_decoded.strip()
        if len(payload) >= 16:
            try:
                decrypted = _apply_decrypt(resp_fn, payload, key, iv, pass_)
                # 元数据标签如 [direct key (16B), AES-ECB, gzip]\nok 是有效结果
                # 错误消息如 [Error: ...] 或 [pycryptodome ...] 需要过滤
                is_error = decrypted.startswith("[") and "\n" not in decrypted and len(decrypted) < 80
                if not is_error:
                    response_results.append({"param": "body", "original": payload[:200],
                        "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
            except Exception as e:
                response_results.append({"param": "body", "original": payload[:200],
                    "original_len": len(payload), "decrypted": f"[Error: {e}]", "decrypted_len": 0})
        # Also try base64 params within response body (some shells embed encrypted params)
        if not response_results:
            for pname, payload in _find_base64_params(resp_body):
                if len(payload) >= 20:
                    try:
                        decrypted = _apply_decrypt(resp_fn, payload, key, iv, pass_)
                        is_error = decrypted.startswith("[") and "\n" not in decrypted and len(decrypted) < 80
                        if not is_error:
                            response_results.append({"param": pname, "original": payload[:200],
                                "original_len": len(payload), "decrypted": decrypted, "decrypted_len": len(decrypted)})
                    except Exception:
                        continue

    # Backward-compatible flat results (request results only)
    results = request_results

    return {
        "transaction_id": tx.get("id"),
        "uri": uri,
        "method": method,
        "type": rule_id,
        "type_name": ws_info.get("type_name", rule_id),
        "key": key,
        "request_results": request_results,
        "response_results": response_results,
        "results": results,
    }


def analyze_session(http_transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for tx in http_transactions:
        try:
            ws_info = analyze_transaction(tx)
            if not ws_info:
                continue
            # 尝试第一种匹配类型
            decrypted = decrypt_transaction(tx, ws_info)
            if decrypted.get("request_results") or decrypted.get("response_results"):
                findings.append(decrypted)
                continue
            # 第一种类型没解出结果，尝试其他匹配类型
            all_types = ws_info.get("all_types", [])
            for alt_type in all_types[1:]:
                alt_info = dict(ws_info)
                alt_info["type"] = alt_type
                alt_info["type_name"] = WEBSHELL_DECRYPT_RULES.get(alt_type, {}).get("name", alt_type)
                alt_info["key"] = extract_key(
                    tx.get("responseBody", "") or "", alt_type
                ) or extract_key(
                    tx.get("requestBody", "") or "", alt_type
                ) or ws_info.get("key", "")
                try:
                    decrypted = decrypt_transaction(tx, alt_info)
                    if decrypted.get("request_results") or decrypted.get("response_results"):
                        findings.append(decrypted)
                        break
                except Exception:
                    continue
        except Exception:
            continue
    return findings


# ============================================================================
# ============================================================================
# HTTP packet formatting
# ============================================================================

def _format_http_request(tx: Dict[str, Any]) -> str:
    """将事务的请求部分格式化为可读的 HTTP 报文。"""
    method = tx.get("method", "GET")
    uri = tx.get("uri", "/")
    headers = tx.get("requestHeaders", {}) or {}
    body = tx.get("requestBody", "") or ""
    lines = [f"{method} {uri} HTTP/1.1"]
    for k, v in headers.items():
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v)
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)


def _format_http_response(tx: Dict[str, Any]) -> str:
    """将事务的响应部分格式化为可读的 HTTP 报文。"""
    headers = tx.get("responseHeaders", {}) or {}
    body = tx.get("responseBody", "") or ""
    status = headers.get("Status-Line", headers.get("status", "HTTP/1.1 200 OK"))
    lines = [str(status)]
    for k, v in headers.items():
        if k in ("Status-Line", "status"):
            continue
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v)
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)


# FastAPI registration helper
# ============================================================================

def register(app):
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
                "needs_key": rule.get("needs_key", False),
                "needs_iv": rule.get("needs_iv", False),
                "needs_pass": rid == "godzilla",
                "manual_only": rule.get("manual_only", False),
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
        try:
            ws_info = analyze_transaction(tx)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"分析事务失败: {e}")
        if not ws_info:
            raise HTTPException(status_code=404, detail="No webshell detected in this transaction")
        custom_key = body.get("key", "")
        if custom_key:
            ws_info["key"] = custom_key
        try:
            result = decrypt_transaction(tx, ws_info)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"解密失败: {e}")
        return {
            "transaction_id": tx_id,
            "uri": result.get("uri", ""),
            "method": result.get("method", ""),
            "type": result.get("type", ""),
            "type_name": result.get("type_name", ""),
            "key": ws_info.get("key", ""),
            "request_results": result.get("request_results", []),
            "response_results": result.get("response_results", []),
            "results": result.get("results", []),
        }

    @app.post("/api/session/{sid}/webshell/decrypt/{tx_id}/manual")
    def post_webshell_manual_decrypt(sid: str, tx_id: int, body: dict = None):
        if body is None:
            body = {}
        ws_type = body.get("type", "auto")
        ws_key = body.get("key", "")
        ws_iv = body.get("iv", "")
        ws_param = body.get("param", "")
        ws_pass = body.get("pass", "")

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

        if ws_type == "auto":
            results = []
            for rid, rule in WEBSHELL_DECRYPT_RULES.items():
                if rid == "generic" or rule.get("manual_only"):
                    continue
                ws_info = {"type": rid, "type_name": rule["name"], "key": ws_key,
                           "iv": ws_iv, "param": ws_param, "pass": ws_pass}
                try:
                    dec_result = decrypt_transaction(tx, ws_info)
                except Exception:
                    continue
                if dec_result.get("request_results") or dec_result.get("response_results"):
                    results.append({
                        "type": rid,
                        "type_name": rule["name"],
                        "key": ws_key,
                        "request_results": dec_result.get("request_results", []),
                        "response_results": dec_result.get("response_results", []),
                    })
            if not results:
                ws_info = {"type": "generic", "type_name": "Generic", "key": ws_key,
                           "iv": ws_iv, "param": ws_param, "pass": ws_pass}
                try:
                    dec_result = decrypt_transaction(tx, ws_info)
                except Exception:
                    dec_result = {}
                if dec_result.get("request_results"):
                    results.append({
                        "type": "generic",
                        "type_name": "Generic",
                        "key": ws_key,
                        "request_results": dec_result.get("request_results", []),
                        "response_results": dec_result.get("response_results", []),
                    })
            return {
                "transaction_id": tx_id,
                "mode": "auto",
                "attempts": results,
                "request_packet": _format_http_request(tx),
                "response_packet": _format_http_response(tx),
                "method": tx.get("method", ""),
                "uri": tx.get("uri", ""),
            }

        rule = WEBSHELL_DECRYPT_RULES.get(ws_type)
        if not rule:
            raise HTTPException(status_code=400, detail=f"Unknown webshell type: {ws_type}. Available: {', '.join(WEBSHELL_DECRYPT_RULES.keys())}")
        ws_info = {"type": ws_type, "type_name": rule["name"], "key": ws_key,
                   "iv": ws_iv, "param": ws_param, "pass": ws_pass}
        try:
            result = decrypt_transaction(tx, ws_info)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"解密失败: {e}")
        return {
            "transaction_id": tx_id,
            "mode": "manual",
            "type": ws_type,
            "type_name": rule["name"],
            "key": ws_key,
            "iv": ws_iv,
            "pass": ws_pass,
            "request_results": result.get("request_results", []),
            "response_results": result.get("response_results", []),
            "results": result.get("results", []),
            "request_packet": _format_http_request(tx),
            "response_packet": _format_http_response(tx),
            "method": tx.get("method", ""),
            "uri": tx.get("uri", ""),
        }

    @app.post("/api/session/{sid}/webshell/decrypt/raw")
    def post_webshell_raw_decrypt(sid: str, body: dict = None):
        """Raw data decryption: paste arbitrary data and specify type/key to decrypt."""
        if body is None:
            body = {}
        data_b64 = body.get("data", "")
        ws_type = body.get("type", "base64")
        ws_key = body.get("key", "")
        ws_iv = body.get("iv", "")
        ws_pass = body.get("pass", "")

        if not data_b64:
            raise HTTPException(status_code=400, detail="No data provided")

        # 智能处理输入：先 URL 解码，再提取 key=value 中的 value
        data_b64 = urllib.parse.unquote(data_b64.strip())
        if "=" in data_b64 and "&" not in data_b64 and not data_b64.startswith("http"):
            parts = data_b64.split("=", 1)
            if len(parts) == 2 and len(parts[1]) > 10:
                data_b64 = parts[1]

        rule = WEBSHELL_DECRYPT_RULES.get(ws_type)
        if not rule:
            raise HTTPException(status_code=400, detail=f"Unknown type: {ws_type}. Available: {', '.join(WEBSHELL_DECRYPT_RULES.keys())}")

        # 尝试 decrypt_resp 优先（处理 MD5 包裹等），回退到 decrypt_req / decrypt
        decrypt_fns = []
        if rule.get("decrypt_resp"):
            decrypt_fns.append(("resp", rule["decrypt_resp"]))
        if rule.get("decrypt_req"):
            decrypt_fns.append(("req", rule["decrypt_req"]))
        if rule.get("decrypt"):
            decrypt_fns.append(("generic", rule["decrypt"]))
        if not decrypt_fns:
            raise HTTPException(status_code=400, detail=f"No decrypt function for type: {ws_type}")

        decrypted = None
        for label, fn in decrypt_fns:
            try:
                result = _apply_decrypt(fn, data_b64, ws_key, ws_iv, ws_pass)
                # 如果不是纯错误消息，就采用
                is_err = result.startswith("[") and "\n" not in result and len(result) < 80
                if not is_err:
                    decrypted = result
                    break
                if decrypted is None:
                    decrypted = result  # 保留第一个结果作为回退
            except Exception as e:
                if decrypted is None:
                    decrypted = f"[Decrypt Error: {e}]"

        return {
            "mode": "raw",
            "type": ws_type,
            "type_name": rule["name"],
            "key": ws_key,
            "iv": ws_iv,
            "pass": ws_pass,
            "original_len": len(data_b64),
            "decrypted": decrypted,
            "decrypted_len": len(decrypted),
        }
