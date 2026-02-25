"""
TOTP (Time-based One-Time Password) implementation following RFC 6238.

Produces codes identical to Google Authenticator.
"""

import hashlib
import hmac
import struct
import time
from enum import Enum
from typing import Optional


class Algorithm(str, Enum):
    """Supported HMAC algorithms."""

    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"


_ALG_MAP: dict[str, str] = {
    Algorithm.SHA1: "sha1",
    Algorithm.SHA256: "sha256",
    Algorithm.SHA512: "sha512",
}


def _hotp_value(secret_bytes: bytes, counter: int, digits: int, algorithm: str) -> str:
    """
    Core HOTP computation (RFC 4226 §5).

    Args:
        secret_bytes: Raw decoded secret.
        counter:      8-byte counter value.
        digits:       Number of OTP digits (6 or 8).
        algorithm:    Hash algorithm name (sha1 / sha256 / sha512).

    Returns:
        Zero-padded OTP string.
    """
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, msg, algorithm).digest()

    # Dynamic truncation
    offset = digest[-1] & 0x0F
    code = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    otp = code % (10**digits)
    return str(otp).zfill(digits)


def generate_totp(
    secret_bytes: bytes,
    digits: int = 6,
    period: int = 30,
    algorithm: Algorithm = Algorithm.SHA1,
    timestamp: Optional[float] = None,
) -> str:
    """
    Generate a TOTP code.

    Args:
        secret_bytes: Raw (already base32-decoded) secret bytes.
        digits:       Number of digits in the OTP (default 6).
        period:       Time step in seconds (default 30).
        algorithm:    HMAC algorithm (default SHA1 for GA compatibility).
        timestamp:    Override Unix timestamp (uses time.time() if None).

    Returns:
        OTP string, zero-padded to ``digits`` characters.
    """
    t = timestamp if timestamp is not None else time.time()
    counter = int(t) // period
    alg_name = _ALG_MAP[algorithm]
    return _hotp_value(secret_bytes, counter, digits, alg_name)


def remaining_seconds(period: int = 30, timestamp: Optional[float] = None) -> int:
    """Return seconds until the current TOTP window expires."""
    t = timestamp if timestamp is not None else time.time()
    return period - (int(t) % period)


def validate_totp(
    token: str,
    secret_bytes: bytes,
    digits: int = 6,
    period: int = 30,
    algorithm: Algorithm = Algorithm.SHA1,
    window: int = 1,
    timestamp: Optional[float] = None,
) -> bool:
    """
    Validate a TOTP token within ±``window`` time steps.

    Args:
        token:        Token to validate.
        secret_bytes: Raw secret bytes.
        digits:       Expected number of digits.
        period:       Time step in seconds.
        algorithm:    HMAC algorithm.
        window:       Allowed skew in steps (default 1).
        timestamp:    Override Unix timestamp.

    Returns:
        True if the token is valid within the window.
    """
    t = timestamp if timestamp is not None else time.time()
    counter = int(t) // period

    for step in range(-window, window + 1):
        expected = generate_totp(
            secret_bytes,
            digits=digits,
            period=period,
            algorithm=algorithm,
            timestamp=float((counter + step) * period),
        )
        if hmac.compare_digest(token.strip(), expected):
            return True
    return False
