"""
Utility helpers for Authify.
"""

import base64
import re
import unicodedata
from typing import Optional


# ── Base32 ────────────────────────────────────────────────────────────────────

def normalize_secret(secret: str) -> str:
    """
    Normalise a base32 secret: strip spaces, uppercase, add padding.

    Args:
        secret: Raw user-supplied secret string.

    Returns:
        Uppercase base32 string with correct padding.

    Raises:
        ValueError: If the string contains invalid base32 characters.
    """
    secret = secret.strip().upper().replace(" ", "").replace("-", "")
    # Base32 alphabet: A-Z and 2-7
    if not re.fullmatch(r"[A-Z2-7=]+", secret):
        raise ValueError("Secret contains invalid base32 characters.")
    # Pad to multiple of 8
    pad = (8 - len(secret) % 8) % 8
    secret = secret + "=" * pad
    return secret


def decode_secret(secret: str) -> bytes:
    """
    Decode a base32-encoded secret string to raw bytes.

    Args:
        secret: Base32 secret (spaces and dashes are stripped).

    Returns:
        Raw bytes.

    Raises:
        ValueError: On invalid base32 input.
    """
    try:
        return base64.b32decode(normalize_secret(secret), casefold=True)
    except Exception as exc:
        raise ValueError(f"Invalid base32 secret: {exc}") from exc


def encode_secret(raw: bytes) -> str:
    """Encode raw bytes as a base32 string (no padding)."""
    return base64.b32encode(raw).decode("ascii").rstrip("=")


# ── URI helpers ───────────────────────────────────────────────────────────────

def sanitise_label(text: str) -> str:
    """Remove control characters and limit label length."""
    text = unicodedata.normalize("NFC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")
    return text[:128].strip()


# ── Time helpers ──────────────────────────────────────────────────────────────

def format_otp(code: str, group: int = 3) -> str:
    """
    Format an OTP code with spaces for readability.

    Example::

        >>> format_otp("123456")
        "123 456"

    Args:
        code:  Digit string.
        group: Digit grouping size.

    Returns:
        Spaced OTP string.
    """
    return " ".join(code[i : i + group] for i in range(0, len(code), group))


# ── Validation ────────────────────────────────────────────────────────────────

def validate_digits(digits: int) -> None:
    if digits not in (6, 8):
        raise ValueError("Digits must be 6 or 8.")


def validate_period(period: int) -> None:
    if period < 1 or period > 300:
        raise ValueError("Period must be between 1 and 300 seconds.")
