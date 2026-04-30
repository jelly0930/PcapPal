#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
哥斯拉 (Godzilla) 内存马完整加解密脚本
支持 Filter 层 (AES+Base64+MD5) + Payload 层 (GZIP+键值对)
"""

import base64
import gzip
import hashlib
import struct
import sys
from Crypto.Cipher import AES

# ==================== 默认配置（与内存马一致）====================
DEFAULT_KEY = "3c6e0b8a9c15224a"   # AES 密钥字符串（16字节）
DEFAULT_PWD = "pass1024"           # 请求参数名（密码）

# ==================== AES 加解密 ====================
def pad(data: bytes) -> bytes:
    length = 16 - (len(data) % 16)
    return data + bytes([length]) * length

def unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

def aes_decrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data))

# ==================== MD5 校验串 ====================
def compute_md5(pwd: str, key: str) -> str:
    return hashlib.md5((pwd + key).encode()).hexdigest().upper()

# ==================== GZIP 压缩/解压 ====================
def gzip_compress(data: bytes) -> bytes:
    return gzip.compress(data)

def gzip_decompress(data: bytes) -> bytes:
    return gzip.decompress(data)

# ==================== 请求加解密（Filter 层） ====================
def encrypt_request_param(plain: bytes, key: str = DEFAULT_KEY) -> str:
    """将明文（通常是 GZIP 压缩后的键值对）加密为请求参数值（Base64）"""
    key_bytes = key.encode()
    enc = aes_encrypt(plain, key_bytes)
    return base64.b64encode(enc).decode()

def decrypt_request_param(enc_b64: str, key: str = DEFAULT_KEY) -> bytes:
    """解密请求参数值（Base64），返回解密后的字节（通常是 GZIP 数据）"""
    key_bytes = key.encode()
    enc = base64.b64decode(enc_b64)
    return aes_decrypt(enc, key_bytes)

# ==================== 响应加解密（Filter 层 + MD5 包裹） ====================
def encrypt_response_body(result_bytes: bytes, key: str = DEFAULT_KEY, pwd: str = DEFAULT_PWD) -> str:
    """
    将命令执行结果（明文）加密为完整的 HTTP 响应体字符串
    格式：MD5前16字符 + Base64(AES_Encrypt(GZIP(result))) + MD5后16字符
    """
    # 1. GZIP 压缩结果
    compressed = gzip_compress(result_bytes)
    # 2. AES 加密
    key_bytes = key.encode()
    encrypted = aes_encrypt(compressed, key_bytes)
    # 3. Base64 编码
    b64_mid = base64.b64encode(encrypted).decode()
    # 4. 计算 MD5 包裹
    md5_full = compute_md5(pwd, key)
    return md5_full[:16] + b64_mid + md5_full[16:]

def decrypt_response_body(response_str: str, key: str = DEFAULT_KEY, pwd: str = DEFAULT_PWD) -> bytes:
    """
    解密完整的 HTTP 响应体，返回最终的命令执行结果（明文）
    """
    if len(response_str) < 32:
        raise ValueError("响应字符串长度不足32，无法剥离MD5标记")
    # 提取中间部分（去掉前后各16字符）
    middle_b64 = response_str[16:-16]
    # 验证 MD5（可选）
    md5_full = compute_md5(pwd, key)
    if response_str[:16] != md5_full[:16] or response_str[-16:] != md5_full[16:]:
        print("[警告] MD5 标记不匹配，可能是密钥/密码错误或响应格式异常", file=sys.stderr)
    # Base64 解码
    encrypted = base64.b64decode(middle_b64)
    # AES 解密
    key_bytes = key.encode()
    compressed = aes_decrypt(encrypted, key_bytes)
    # GZIP 解压
    return gzip_decompress(compressed)

# ==================== Payload 层的键值对编解码（辅助功能，便于阅读） ====================
def encode_kv_pairs(kv_dict: dict) -> bytes:
    """
    将键值对编码为内存马请求的内层格式（GZIP 压缩前的原始数据）
    格式：0x02 + key + 0x02 + 4字节长度（小端）+ value
    """
    out = bytearray()
    for key, value in kv_dict.items():
        key_bytes = key.encode('utf-8')
        if isinstance(value, str):
            value_bytes = value.encode('utf-8')
        elif isinstance(value, bytes):
            value_bytes = value
        else:
            value_bytes = str(value).encode('utf-8')
        out.append(0x02)
        out.extend(key_bytes)
        out.append(0x02)
        out.extend(struct.pack('<I', len(value_bytes)))  # 小端4字节长度
        out.extend(value_bytes)
    return bytes(out)

def decode_kv_pairs(data: bytes) -> dict:
    """
    从内存马请求的内层数据（GZIP 解压后）中解析键值对
    """
    result = {}
    i = 0
    while i < len(data):
        if data[i] != 0x02:
            i += 1
            continue
        i += 1
        # 读取 key
        key_start = i
        while i < len(data) and data[i] != 0x02:
            i += 1
        if i >= len(data):
            break
        key = data[key_start:i].decode('utf-8')
        i += 1
        # 读取 4 字节长度
        if i + 4 > len(data):
            break
        length = struct.unpack('<I', data[i:i+4])[0]
        i += 4
        if i + length > len(data):
            break
        value = data[i:i+length]
        result[key] = value
        i += length
    return result

# ==================== 交互式菜单 ====================
def interactive():
    print("=" * 60)
    print("哥斯拉 (Godzilla) 内存马完整加解密工具")
    print("支持 Filter 层 (AES+Base64+MD5) + Payload 层 (GZIP+键值对)")
    print("=" * 60)

    key = input(f"请输入 AES 密钥字符串 (默认 {DEFAULT_KEY}): ").strip()
    if not key:
        key = DEFAULT_KEY
    pwd = input(f"请输入密码 (参数名, 默认 {DEFAULT_PWD}): ").strip()
    if not pwd:
        pwd = DEFAULT_PWD

    print(f"\n当前配置: KEY = {key}, PWD = {pwd}")
    print(f"MD5 包裹串: {compute_md5(pwd, key)}\n")

    while True:
        print("\n请选择操作：")
        print("1. 解密请求参数（从 Base64 到明文键值对）")
        print("2. 加密请求参数（从明文键值对到 Base64）")
        print("3. 解密响应内容（从完整响应字符串到最终结果）")
        print("4. 加密响应内容（从明文结果到完整响应字符串）")
        print("5. 解析键值对（不解压，仅解析格式）")
        print("0. 退出")
        choice = input("请输入编号: ").strip()

        if choice == "0":
            break
        elif choice == "1":
            b64 = input("请输入请求参数的 Base64 值: ").strip()
            try:
                decrypted = decrypt_request_param(b64, key)
                print(f"AES 解密后的数据长度: {len(decrypted)} 字节")
                # 尝试 GZIP 解压
                try:
                    decompressed = gzip_decompress(decrypted)
                    print("GZIP 解压成功，解析键值对如下：")
                    kv = decode_kv_pairs(decompressed)
                    for k, v in kv.items():
                        # 尝试将值显示为字符串（如果是文本）
                        try:
                            val_str = v.decode('utf-8')
                            print(f"  {k} = {val_str}")
                        except UnicodeDecodeError:
                            print(f"  {k} = (二进制, {len(v)} 字节)")
                except gzip.BadGzipFile:
                    print("非 GZIP 数据（可能为原始字节码或未压缩数据），直接显示十六进制前256字节:")
                    print(decrypted[:256].hex())
            except Exception as e:
                print(f"错误: {e}")

        elif choice == "2":
            print("请输入键值对，每行格式: key=value (字符串)，空行结束")
            kv = {}
            while True:
                line = input().strip()
                if not line:
                    break
                if '=' not in line:
                    print("忽略无效行，需包含 =")
                    continue
                k, v = line.split('=', 1)
                kv[k.strip()] = v.strip()
            if not kv:
                print("没有输入任何键值对")
                continue
            # 编码为原始数据
            raw = encode_kv_pairs(kv)
            print(f"原始键值对编码后长度: {len(raw)} 字节")
            # GZIP 压缩
            compressed = gzip_compress(raw)
            print(f"GZIP 压缩后长度: {len(compressed)} 字节")
            # AES + Base64
            enc_b64 = encrypt_request_param(compressed, key)
            print(f"请求参数值 (Base64):\n{enc_b64}")

        elif choice == "3":
            resp = input("请输入完整的响应字符串: ").strip()
            try:
                result = decrypt_response_body(resp, key, pwd)
                print(f"最终结果长度: {len(result)} 字节")
                # 尝试显示为文本
                try:
                    print("明文结果:")
                    print(result.decode('utf-8'))
                except UnicodeDecodeError:
                    print("二进制数据，显示十六进制前256字节:")
                    print(result[:256].hex())
            except Exception as e:
                print(f"错误: {e}")

        elif choice == "4":
            plain_result = input("请输入要加密的命令执行结果（文本）: ").strip()
            result_bytes = plain_result.encode('utf-8')
            full_response = encrypt_response_body(result_bytes, key, pwd)
            print(f"生成的完整响应字符串:\n{full_response}")

        elif choice == "5":
            data_hex = input("请输入原始数据（十六进制）: ").strip()
            try:
                data = bytes.fromhex(data_hex)
                kv = decode_kv_pairs(data)
                print("解析出的键值对:")
                for k, v in kv.items():
                    try:
                        print(f"  {k} = {v.decode('utf-8')}")
                    except UnicodeDecodeError:
                        print(f"  {k} = (二进制, {len(v)} 字节)")
            except Exception as e:
                print(f"错误: {e}")

        else:
            print("无效选项，请重新输入")

if __name__ == "__main__":
    interactive()