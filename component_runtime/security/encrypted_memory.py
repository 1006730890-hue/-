"""Authenticated memory envelopes. Decryption never changes source trust."""
from __future__ import annotations

import base64
import json
import os
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MARKER = "XIAOZHI_AES_GCM_V1:"
ASCII_MARKER = "XIAOZHI_ASCII_HEX_V1:"
_AAD = b"xiaozhi-memory-v1"


def _key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=16384, r=8, p=1).derive(password.encode("utf-8"))


def encrypt_memory(text: str, password: str) -> str:
    salt, nonce = os.urandom(16), os.urandom(12)
    ciphertext = AESGCM(_key(password, salt)).encrypt(nonce, text.encode("utf-8"), _AAD)
    envelope = {"algorithm": "AES-256-GCM", "kdf": "scrypt-N16384-r8-p1",
                "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode()}
    return MARKER + json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))


def encode_ascii_memory(text: str) -> str:
    """Encode an English hidden instruction as an ASCII hex envelope."""
    raw = text.encode("ascii")
    return ASCII_MARKER + raw.hex()


def is_encrypted_memory(content: str) -> bool:
    return MARKER in content or ASCII_MARKER in content


def decrypt_memory(content: str, request: str) -> str:
    """Only inspect when the current user explicitly supplies a password."""
    if ASCII_MARKER in content:
        if "ascii" not in request.casefold() or "码表" not in request:
            raise ValueError("当前请求未提供 ASCII 解码规则，密文保持隔离")
        encoded = content.split(ASCII_MARKER, 1)[1].strip()
        if not encoded or len(encoded) > 20000 or len(encoded) % 2:
            raise ValueError("无效的 ASCII 密文")
        try:
            return bytes.fromhex(encoded).decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("ASCII 密文解码失败") from exc
    match = re.search(r"解密口令[：:]\s*([^\s。；;，,]+)", request)
    if not match:
        raise ValueError("当前用户未提供解密口令，密文保持隔离")
    if len(content) > 20000:
        raise ValueError("加密记忆超过检查大小限制")
    envelope = json.loads(content.split(MARKER, 1)[1])
    if envelope.get("algorithm") != "AES-256-GCM" or envelope.get("kdf") != "scrypt-N16384-r8-p1":
        raise ValueError("不支持的记忆加密格式")
    salt, nonce, ciphertext = (base64.b64decode(envelope[k], validate=True)
                               for k in ("salt", "nonce", "ciphertext"))
    if len(salt) != 16 or len(nonce) != 12:
        raise ValueError("无效的加密记忆参数")
    return AESGCM(_key(match[1], salt)).decrypt(nonce, ciphertext, _AAD).decode("utf-8")
