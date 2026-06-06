"""Pure crypto logic — encrypt, decrypt, hash, generate. No Telegram imports."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import string
from typing import NamedTuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ── Result types ──────────────────────────────────────────────────────────────

class CryptoResult(NamedTuple):
    success: bool
    data: str | None = None
    error: str | None = None


class HashResult(NamedTuple):
    algorithm: str
    hex_digest: str


# ── Key derivation ────────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """Derive a key from password using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(password.encode("utf-8"))


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

def aes_encrypt(plaintext: str, password: str) -> CryptoResult:
    """Encrypt plaintext with AES-256-GCM using a password.

    Output format (base64): salt(16) + nonce(12) + ciphertext+tag
    """
    if not plaintext:
        return CryptoResult(False, error="❌ Nothing to encrypt — send some text.")
    if not password:
        return CryptoResult(False, error="❌ Password is required.")

    try:
        salt = os.urandom(16)
        key = _derive_key(password, salt)
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        payload = base64.b64encode(salt + nonce + ct).decode("ascii")
        return CryptoResult(True, data=payload)
    except Exception as e:
        return CryptoResult(False, error=f"❌ Encryption failed: {e}")


def aes_decrypt(ciphertext_b64: str, password: str) -> CryptoResult:
    """Decrypt AES-256-GCM ciphertext produced by aes_encrypt."""
    if not ciphertext_b64:
        return CryptoResult(False, error="❌ Nothing to decrypt — send the encrypted text.")
    if not password:
        return CryptoResult(False, error="❌ Password is required.")

    try:
        raw = base64.b64decode(ciphertext_b64)
        if len(raw) < 29:  # 16 salt + 12 nonce + 1 tag minimum
            return CryptoResult(False, error="❌ Invalid ciphertext — too short.")
        salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ct, None).decode("utf-8")
        return CryptoResult(True, data=plaintext)
    except Exception:
        return CryptoResult(False, error="❌ Decryption failed — wrong password or corrupted data.")


# ── Fernet ────────────────────────────────────────────────────────────────────

def fernet_generate_key() -> str:
    """Generate a new Fernet key (base64-encoded)."""
    return Fernet.generate_key().decode("ascii")


def fernet_encrypt(plaintext: str, key: str) -> CryptoResult:
    """Encrypt plaintext with Fernet (symmetric, authenticated)."""
    if not plaintext:
        return CryptoResult(False, error="❌ Nothing to encrypt.")
    if not key:
        return CryptoResult(False, error="❌ Fernet key is required.")

    try:
        f = Fernet(key.encode("ascii") if isinstance(key, str) else key)
        token = f.encrypt(plaintext.encode("utf-8")).decode("ascii")
        return CryptoResult(True, data=token)
    except Exception as e:
        return CryptoResult(False, error=f"❌ Fernet encryption failed: {e}")


def fernet_decrypt(token: str, key: str) -> CryptoResult:
    """Decrypt a Fernet token."""
    if not token:
        return CryptoResult(False, error="❌ Nothing to decrypt.")
    if not key:
        return CryptoResult(False, error="❌ Fernet key is required.")

    try:
        f = Fernet(key.encode("ascii") if isinstance(key, str) else key)
        plaintext = f.decrypt(token.encode("ascii"), ttl=None).decode("utf-8")
        return CryptoResult(True, data=plaintext)
    except Exception:
        return CryptoResult(False, error="❌ Fernet decryption failed — wrong key or expired token.")


# ── Base64 ────────────────────────────────────────────────────────────────────

def b64_encode(text: str) -> CryptoResult:
    if not text:
        return CryptoResult(False, error="❌ Nothing to encode.")
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return CryptoResult(True, data=encoded)


def b64_decode(text: str) -> CryptoResult:
    if not text:
        return CryptoResult(False, error="❌ Nothing to decode.")
    try:
        decoded = base64.b64decode(text).decode("utf-8")
        return CryptoResult(True, data=decoded)
    except Exception:
        return CryptoResult(False, error="❌ Invalid Base64 text.")


# ── ROT13 ─────────────────────────────────────────────────────────────────────

def rot13(text: str) -> CryptoResult:
    if not text:
        return CryptoResult(False, error="❌ Nothing to process.")
    import codecs
    return CryptoResult(True, data=codecs.encode(text, "rot_13"))


# ── Caesar cipher ─────────────────────────────────────────────────────────────

def caesar_encrypt(text: str, shift: int) -> CryptoResult:
    if not text:
        return CryptoResult(False, error="❌ Nothing to encrypt.")
    result: list[str] = []
    for ch in text:
        if ch.isascii() and ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return CryptoResult(True, data="".join(result))


def caesar_decrypt(text: str, shift: int) -> CryptoResult:
    return caesar_encrypt(text, -shift)


# ── Hashing ───────────────────────────────────────────────────────────────────

SUPPORTED_HASHES = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}


def hash_text(text: str, algorithm: str = "sha256") -> HashResult | CryptoResult:
    if not text:
        return CryptoResult(False, error="❌ Nothing to hash.")
    algo = algorithm.lower().replace("-", "").replace("_", "")
    # Normalize aliases
    algo_map = {
        "sha256": "sha256", "sha512": "sha512", "sha1": "sha1", "md5": "md5",
        "sha3256": "sha3_256", "sha3512": "sha3_512",
        "blake2b": "blake2b", "blake2s": "blake2s",
    }
    resolved = algo_map.get(algo)
    if not resolved or resolved not in SUPPORTED_HASHES:
        return CryptoResult(False, error=f"❌ Unsupported algorithm: {algorithm}")

    h = SUPPORTED_HASHES[resolved](text.encode("utf-8")).hexdigest()
    return HashResult(algorithm=resolved, hex_digest=h)


def hmac_text(text: str, key: str, algorithm: str = "sha256") -> CryptoResult:
    if not text:
        return CryptoResult(False, error="❌ Nothing to sign.")
    if not key:
        return CryptoResult(False, error="❌ HMAC key is required.")

    algo_map = {"sha256": "sha256", "sha512": "sha512", "sha1": "sha1", "md5": "md5"}
    resolved = algo_map.get(algorithm.lower().replace("-", ""))
    if not resolved:
        return CryptoResult(False, error=f"❌ Unsupported HMAC algorithm: {algorithm}")

    digest = hmac.new(key.encode("utf-8"), text.encode("utf-8"), getattr(hashlib, resolved)).hexdigest()
    return CryptoResult(True, data=digest)


# ── Password generation ───────────────────────────────────────────────────────

def generate_password(length: int = 24) -> str:
    """Generate a cryptographically secure random password."""
    length = max(8, min(128, length))
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        # Ensure at least one of each category
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in "!@#$%^&*" for c in pw)):
            return pw


# ── File encryption (AES-256-GCM) ────────────────────────────────────────────

def file_encrypt(data: bytes, password: str) -> CryptoResult:
    """Encrypt file bytes with AES-256-GCM. Returns base64 payload."""
    if not data:
        return CryptoResult(False, error="❌ Empty file.")
    if not password:
        return CryptoResult(False, error="❌ Password is required.")

    try:
        salt = os.urandom(16)
        key = _derive_key(password, salt)
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, None)
        payload = base64.b64encode(salt + nonce + ct).decode("ascii")
        return CryptoResult(True, data=payload)
    except Exception as e:
        return CryptoResult(False, error=f"❌ File encryption failed: {e}")


def file_decrypt(payload_b64: str, password: str) -> tuple[bytes | None, str | None]:
    """Decrypt file bytes from base64 payload. Returns (data, error)."""
    if not payload_b64:
        return None, "❌ Nothing to decrypt."
    if not password:
        return None, "❌ Password is required."

    try:
        raw = base64.b64decode(payload_b64)
        if len(raw) < 29:
            return None, "❌ Invalid encrypted file — too short."
        salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        data = aesgcm.decrypt(nonce, ct, None)
        return data, None
    except Exception:
        return None, "❌ Decryption failed — wrong password or corrupted file."
