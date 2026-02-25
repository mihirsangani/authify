"""
Storage-level encryption helpers.

Wraps authify.core.crypto to provide field-level encryption for database
values. The caller is responsible for key management; keys are never written
to disk through this module.
"""

import base64
from typing import Optional

from core import crypto


class FieldEncryptor:
    """Encrypt / decrypt individual string fields using AES-256-GCM."""

    def __init__(self, key: bytes) -> None:
        """
        Args:
            key: 32-byte AES key derived with :func:`authify.core.crypto.derive_key`.
        """
        if len(key) != crypto.KEY_SIZE:
            raise ValueError("Key must be 32 bytes.")
        self._key = key

    # ── Public API ───────────────────────────────────────────────────────

    def encrypt_field(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string and return a base64-encoded blob.

        Args:
            plaintext: String to encrypt.

        Returns:
            URL-safe base64 string safe for SQLite storage.
        """
        blob = crypto.encrypt(plaintext.encode("utf-8"), self._key)
        return base64.urlsafe_b64encode(blob).decode("ascii")

    def decrypt_field(self, encoded: str) -> str:
        """
        Decrypt a base64 blob produced by :meth:`encrypt_field`.

        Args:
            encoded: URL-safe base64 encoded ciphertext blob.

        Returns:
            Original plaintext string.

        Raises:
            cryptography.exceptions.InvalidTag: On integrity/auth failure.
        """
        blob = base64.urlsafe_b64decode(encoded.encode("ascii"))
        return crypto.decrypt(blob, self._key).decode("utf-8")

    def wipe_key(self) -> None:
        """Overwrite the in-memory key with zeros (best-effort)."""
        self._key = b"\x00" * len(self._key)
