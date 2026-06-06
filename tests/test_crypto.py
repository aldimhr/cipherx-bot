"""Tests for crypto core logic."""

import pytest
from cryptobot.crypto import (
    aes_decrypt,
    aes_encrypt,
    b64_decode,
    b64_encode,
    caesar_decrypt,
    caesar_encrypt,
    fernet_decrypt,
    fernet_encrypt,
    fernet_generate_key,
    file_decrypt,
    file_encrypt,
    generate_password,
    hash_text,
    hmac_text,
    rot13,
)


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

class TestAES:
    def test_roundtrip(self):
        plaintext = "Hello, CipherX!"
        password = "s3cur3p@ssw0rd"
        enc = aes_encrypt(plaintext, password)
        assert enc.success
        assert enc.data != plaintext

        dec = aes_decrypt(enc.data, password)
        assert dec.success
        assert dec.data == plaintext

    def test_wrong_password(self):
        enc = aes_encrypt("secret", "correct_password")
        assert enc.success
        dec = aes_decrypt(enc.data, "wrong_password")
        assert not dec.success
        assert "Decryption failed" in dec.error

    def test_empty_plaintext(self):
        result = aes_encrypt("", "password")
        assert not result.success

    def test_empty_password(self):
        result = aes_encrypt("text", "")
        assert not result.success

    def test_different_ciphertexts(self):
        """Same plaintext should produce different ciphertexts (random salt+nonce)."""
        enc1 = aes_encrypt("same text", "password")
        enc2 = aes_encrypt("same text", "password")
        assert enc1.data != enc2.data

    def test_decrypt_invalid_base64(self):
        result = aes_decrypt("not-valid-base64!!!", "password")
        assert not result.success

    def test_decrypt_too_short(self):
        import base64
        result = aes_decrypt(base64.b64encode(b"short").decode(), "password")
        assert not result.success
        assert "too short" in result.error


# ── Fernet ────────────────────────────────────────────────────────────────────

class TestFernet:
    def test_roundtrip(self):
        key = fernet_generate_key()
        enc = fernet_encrypt("hello fernet", key)
        assert enc.success
        dec = fernet_decrypt(enc.data, key)
        assert dec.success
        assert dec.data == "hello fernet"

    def test_wrong_key(self):
        key1 = fernet_generate_key()
        key2 = fernet_generate_key()
        enc = fernet_encrypt("secret", key1)
        assert enc.success
        dec = fernet_decrypt(enc.data, key2)
        assert not dec.success

    def test_empty_plaintext(self):
        key = fernet_generate_key()
        result = fernet_encrypt("", key)
        assert not result.success

    def test_empty_key(self):
        result = fernet_encrypt("text", "")
        assert not result.success


# ── Base64 ────────────────────────────────────────────────────────────────────

class TestBase64:
    def test_roundtrip(self):
        enc = b64_encode("Hello World")
        assert enc.success
        dec = b64_decode(enc.data)
        assert dec.success
        assert dec.data == "Hello World"

    def test_unicode(self):
        enc = b64_encode("🔐 Unicode ✓")
        assert enc.success
        dec = b64_decode(enc.data)
        assert dec.success
        assert dec.data == "🔐 Unicode ✓"

    def test_decode_invalid(self):
        result = b64_decode("not!!valid!!base64")
        assert not result.success

    def test_empty(self):
        assert not b64_encode("").success
        assert not b64_decode("").success


# ── ROT13 ─────────────────────────────────────────────────────────────────────

class TestROT13:
    def test_roundtrip(self):
        r1 = rot13("Hello")
        assert r1.success
        r2 = rot13(r1.data)
        assert r2.success
        assert r2.data == "Hello"

    def test_known(self):
        r = rot13("abc")
        assert r.success
        assert r.data == "nop"


# ── Caesar ────────────────────────────────────────────────────────────────────

class TestCaesar:
    def test_roundtrip(self):
        enc = caesar_encrypt("Hello World", 5)
        assert enc.success
        dec = caesar_decrypt(enc.data, 5)
        assert dec.success
        assert dec.data == "Hello World"

    def test_shift_26_identity(self):
        r = caesar_encrypt("test", 26)
        assert r.success
        assert r.data == "test"

    def test_non_alpha_preserved(self):
        r = caesar_encrypt("Hello, World! 123", 3)
        assert r.success
        assert "123" in r.data
        assert "," in r.data

    def test_empty(self):
        assert not caesar_encrypt("", 3).success


# ── Hashing ───────────────────────────────────────────────────────────────────

class TestHash:
    def test_sha256_known(self):
        hr = hash_text("hello", "sha256")
        assert hasattr(hr, "hex_digest")
        assert hr.hex_digest == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_md5_known(self):
        hr = hash_text("hello", "md5")
        assert hasattr(hr, "hex_digest")
        assert hr.hex_digest == "5d41402abc4b2a76b9719d911017c592"

    def test_all_algorithms(self):
        for algo in ["md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"]:
            hr = hash_text("test", algo)
            assert hasattr(hr, "hex_digest"), f"Failed for {algo}"
            assert len(hr.hex_digest) > 0

    def test_unsupported(self):
        result = hash_text("test", "whirlpool")
        assert hasattr(result, "success") and not result.success

    def test_empty(self):
        result = hash_text("", "sha256")
        assert hasattr(result, "success") and not result.success


# ── HMAC ──────────────────────────────────────────────────────────────────────

class TestHMAC:
    def test_sha256(self):
        r = hmac_text("hello", "secret_key", "sha256")
        assert r.success
        assert len(r.data) == 64  # SHA-256 hex is 64 chars

    def test_deterministic(self):
        r1 = hmac_text("msg", "key", "sha256")
        r2 = hmac_text("msg", "key", "sha256")
        assert r1.data == r2.data

    def test_different_keys(self):
        r1 = hmac_text("msg", "key1", "sha256")
        r2 = hmac_text("msg", "key2", "sha256")
        assert r1.data != r2.data

    def test_empty_text(self):
        r = hmac_text("", "key", "sha256")
        assert not r.success

    def test_empty_key(self):
        r = hmac_text("msg", "", "sha256")
        assert not r.success


# ── Password Generation ──────────────────────────────────────────────────────

class TestGenerate:
    def test_default_length(self):
        pw = generate_password()
        assert len(pw) == 24

    def test_custom_length(self):
        pw = generate_password(32)
        assert len(pw) == 32

    def test_min_length_clamped(self):
        pw = generate_password(1)
        assert len(pw) >= 8

    def test_max_length_clamped(self):
        pw = generate_password(999)
        assert len(pw) <= 128

    def test_has_all_categories(self):
        pw = generate_password(24)
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(c in "!@#$%^&*" for c in pw)

    def test_uniqueness(self):
        passwords = {generate_password(32) for _ in range(10)}
        assert len(passwords) == 10  # All different


# ── File Encryption ──────────────────────────────────────────────────────────

class TestFileEncrypt:
    def test_roundtrip(self):
        data = b"Binary file content \x00\x01\x02\xff"
        password = "file_password"
        enc = file_encrypt(data, password)
        assert enc.success

        dec_data, err = file_decrypt(enc.data, password)
        assert err is None
        assert dec_data == data

    def test_wrong_password(self):
        enc = file_encrypt(b"data", "correct")
        assert enc.success
        _, err = file_decrypt(enc.data, "wrong")
        assert err is not None

    def test_empty_data(self):
        result = file_encrypt(b"", "password")
        assert not result.success

    def test_large_data(self):
        data = b"x" * (1024 * 1024)  # 1 MB
        enc = file_encrypt(data, "password")
        assert enc.success
        dec_data, err = file_decrypt(enc.data, "password")
        assert err is None
        assert len(dec_data) == 1024 * 1024
