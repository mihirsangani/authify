"""
HOTP (HMAC-based One-Time Password) implementation following RFC 4226.
"""

import hmac
import struct
from typing import Optional

from core.totp import Algorithm, _ALG_MAP


def generate_hotp(
    secret_bytes: bytes,
    counter: int,
    digits: int = 6,
    algorithm: Algorithm = Algorithm.SHA1,
) -> str:
    """
    Generate an HOTP code.

    Args:
        secret_bytes: Raw decoded secret bytes.
        counter:      Synchronisation counter value.
        digits:       Number of OTP digits (6 or 8).
        algorithm:    HMAC algorithm.

    Returns:
        Zero-padded OTP string.
    """
    alg_name = _ALG_MAP[algorithm]
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, msg, alg_name).digest()

    offset = digest[-1] & 0x0F
    code = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    otp = code % (10**digits)
    return str(otp).zfill(digits)


def validate_hotp(
    token: str,
    secret_bytes: bytes,
    counter: int,
    digits: int = 6,
    algorithm: Algorithm = Algorithm.SHA1,
    look_ahead: int = 10,
) -> Optional[int]:
    """
    Validate an HOTP token and return the synchronised counter value.

    Args:
        token:       Token to validate.
        secret_bytes: Raw secret bytes.
        counter:     Current counter.
        digits:      Expected OTP length.
        algorithm:   HMAC algorithm.
        look_ahead:  Max steps to search ahead for resync.

    Returns:
        The new counter value if valid, or None if invalid.
    """
    for i in range(look_ahead + 1):
        expected = generate_hotp(secret_bytes, counter + i, digits, algorithm)
        if hmac.compare_digest(token.strip(), expected):
            return counter + i + 1
    return None
