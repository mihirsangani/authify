"""
Cryptographic utilities for Authify.

Key derivation  : PBKDF2-HMAC-SHA256
Encryption      : AES-256-GCM (authenticated encryption)
"""

import hashlib
import hmac
import os
import secrets
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Constants ────────────────────────────────────────────────────────────────

SALT_SIZE = 32          # 256-bit salt
NONCE_SIZE = 12         # 96-bit nonce (GCM recommendation)
KEY_SIZE = 32           # 256-bit AES key
PBKDF2_ITERATIONS = 480_000  # OWASP 2023 recommendation for PBKDF2-SHA256
PBKDF2_HASH = "sha256"


# ── Key derivation ────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from ``password`` using PBKDF2-HMAC-SHA256.

    Args:
        password: Master password (unicode string).
        salt:     Random 32-byte salt.

    Returns:
        32-byte derived key.
    """
    return hashlib.pbkdf2_hmac(
        PBKDF2_HASH,
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,
    )


def generate_salt() -> bytes:
    """Return a cryptographically random 32-byte salt."""
    return secrets.token_bytes(SALT_SIZE)


# ── AES-256-GCM encryption / decryption ──────────────────────────────────────

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Layout of returned ciphertext blob::

        [ nonce (12 bytes) | ciphertext+tag ]

    The GCM tag (16 bytes) is appended by the library automatically.

    Args:
        plaintext: Data to encrypt.
        key:       32-byte AES key.

    Returns:
        Blob containing nonce + ciphertext + tag.

    Raises:
        ValueError: If key length is not 32 bytes.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(blob: bytes, key: bytes) -> bytes:
    """
    Decrypt a blob produced by :func:`encrypt`.

    Args:
        blob: nonce + ciphertext + tag.
        key:  32-byte AES key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If key length is not 32 bytes.
        cryptography.exceptions.InvalidTag: If authentication fails (wrong key
            or tampered data).
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
    nonce = blob[:NONCE_SIZE]
    ciphertext = blob[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ── Convenience: full password-based encrypt / decrypt ───────────────────────

def encrypt_with_password(plaintext: bytes, password: str) -> bytes:
    """
    Derive a key from *password* and encrypt *plaintext*.

    Returned blob layout::

        [ salt (32) | nonce (12) | ciphertext+tag ]

    Args:
        plaintext: Data to encrypt.
        password:  Master password.

    Returns:
        Salt + encrypted blob.
    """
    salt = generate_salt()
    key = derive_key(password, salt)
    encrypted = encrypt(plaintext, key)
    return salt + encrypted


def decrypt_with_password(blob: bytes, password: str) -> bytes:
    """
    Decrypt a blob produced by :func:`encrypt_with_password`.

    Args:
        blob:     salt + nonce + ciphertext + tag.
        password: Master password.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: On authentication failure.
    """
    salt = blob[:SALT_SIZE]
    encrypted = blob[SALT_SIZE:]
    key = derive_key(password, salt)
    return decrypt(encrypted, key)


def constant_time_compare(a: str, b: str) -> bool:
    """Return True if *a* == *b* in constant time (timing-safe)."""
    return hmac.compare_digest(a.encode(), b.encode())
