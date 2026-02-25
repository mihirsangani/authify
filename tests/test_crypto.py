"""Tests for authify.core.crypto."""

import pytest
from cryptography.exceptions import InvalidTag

from core.crypto import (
    SALT_SIZE,
    KEY_SIZE,
    NONCE_SIZE,
    derive_key,
    generate_salt,
    encrypt,
    decrypt,
    encrypt_with_password,
    decrypt_with_password,
)


# ── Key derivation ────────────────────────────────────────────────────────────

def test_derive_key_length() -> None:
    salt = generate_salt()
    key = derive_key("password", salt)
    assert len(key) == KEY_SIZE


def test_derive_key_deterministic() -> None:
    salt = generate_salt()
    k1 = derive_key("hello", salt)
    k2 = derive_key("hello", salt)
    assert k1 == k2


def test_derive_key_different_passwords() -> None:
    salt = generate_salt()
    assert derive_key("password1", salt) != derive_key("password2", salt)


def test_derive_key_different_salts() -> None:
    k1 = derive_key("password", generate_salt())
    k2 = derive_key("password", generate_salt())
    assert k1 != k2


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

def test_encrypt_decrypt_roundtrip() -> None:
    key = derive_key("test", generate_salt())
    plaintext = b"Hello, Authify!"
    blob = encrypt(plaintext, key)
    assert decrypt(blob, key) == plaintext


def test_encrypt_produces_different_blobs() -> None:
    """Each call produces a different nonce → different blob."""
    key = derive_key("test", generate_salt())
    a = encrypt(b"same", key)
    b_ = encrypt(b"same", key)
    assert a != b_


def test_decrypt_wrong_key_raises() -> None:
    key1 = derive_key("correct", generate_salt())
    key2 = derive_key("wrong", generate_salt())
    blob = encrypt(b"secret", key1)
    with pytest.raises(Exception):
        decrypt(blob, key2)


def test_decrypt_tampered_data_raises() -> None:
    key = derive_key("test", generate_salt())
    blob = bytearray(encrypt(b"secret", key))
    blob[-1] ^= 0xFF  # flip a bit in the tag
    with pytest.raises(Exception):
        decrypt(bytes(blob), key)


def test_encrypt_wrong_key_size_raises() -> None:
    with pytest.raises(ValueError):
        encrypt(b"test", b"short_key")


# ── Password-based encrypt / decrypt ─────────────────────────────────────────

def test_password_roundtrip() -> None:
    data = b"my secret totp seed"
    pw = "strong_password_123"
    blob = encrypt_with_password(data, pw)
    assert decrypt_with_password(blob, pw) == data


def test_password_blob_contains_salt() -> None:
    blob = encrypt_with_password(b"data", "pw")
    # First SALT_SIZE bytes should be the salt (non-zero with very high probability)
    assert len(blob) > SALT_SIZE + NONCE_SIZE
    assert blob[:SALT_SIZE] != b"\x00" * SALT_SIZE


def test_password_wrong_password_raises() -> None:
    blob = encrypt_with_password(b"data", "correct")
    with pytest.raises(InvalidTag):
        decrypt_with_password(blob, "wrong")
