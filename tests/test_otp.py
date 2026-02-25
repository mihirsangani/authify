"""Tests for authify.core.totp and authify.core.hotp."""

import base64
import struct
import time

import pytest

from core.totp import Algorithm, generate_totp, remaining_seconds, validate_totp
from core.hotp import generate_hotp, validate_hotp
from core.utils import decode_secret, encode_secret, normalize_secret, format_otp


# ── RFC 4226 Appendix D test vectors ─────────────────────────────────────────
# Secret: "12345678901234567890" (as bytes)
RFC_SECRET = b"12345678901234567890"
RFC_HOTP_EXPECTED = [
    "755224", "287082", "359152", "969429", "338314",
    "254676", "287922", "162583", "399871", "520489",
]


@pytest.mark.parametrize("counter,expected", enumerate(RFC_HOTP_EXPECTED))
def test_hotp_rfc4226_vectors(counter: int, expected: str) -> None:
    code = generate_hotp(RFC_SECRET, counter=counter, digits=6, algorithm=Algorithm.SHA1)
    assert code == expected, f"HOTP counter={counter}: got {code}, expected {expected}"


# ── RFC 6238 TOTP test vectors ────────────────────────────────────────────────
# Source: RFC 6238, Appendix B
# Secrets vary by algorithm per the RFC

_TOTP_VECTORS = [
    # (timestamp, algorithm,  secret_bytes,          expected)
    (59,          Algorithm.SHA1,   b"12345678901234567890",                      "94287082"),
    (59,          Algorithm.SHA256, b"12345678901234567890123456789012",          "46119246"),
    (59,          Algorithm.SHA512, b"1234567890123456789012345678901234567890123456789012345678901234", "90693936"),
    (1111111109,  Algorithm.SHA1,   b"12345678901234567890",                      "07081804"),
    (1111111109,  Algorithm.SHA256, b"12345678901234567890123456789012",          "68084774"),
    (1111111109,  Algorithm.SHA512, b"1234567890123456789012345678901234567890123456789012345678901234", "25091201"),
    (1111111111,  Algorithm.SHA1,   b"12345678901234567890",                      "14050471"),
    (1111111111,  Algorithm.SHA256, b"12345678901234567890123456789012",          "67062674"),
    (1111111111,  Algorithm.SHA512, b"1234567890123456789012345678901234567890123456789012345678901234", "99943326"),
    (20000000000, Algorithm.SHA1,   b"12345678901234567890",                      "65353130"),
    (20000000000, Algorithm.SHA256, b"12345678901234567890123456789012",          "77737706"),
    (20000000000, Algorithm.SHA512, b"1234567890123456789012345678901234567890123456789012345678901234", "47863826"),
]


@pytest.mark.parametrize("ts,alg,secret,expected", _TOTP_VECTORS)
def test_totp_rfc6238_vectors(
    ts: int, alg: Algorithm, secret: bytes, expected: str
) -> None:
    code = generate_totp(
        secret,
        digits=8,
        period=30,
        algorithm=alg,
        timestamp=float(ts),
    )
    assert code == expected, f"TOTP ts={ts} {alg}: got {code}, expected {expected}"


# ── Remaining seconds ─────────────────────────────────────────────────────────

def test_remaining_seconds_range() -> None:
    rem = remaining_seconds(period=30)
    assert 0 < rem <= 30


def test_remaining_seconds_at_boundary() -> None:
    # At exactly t=0 (multiple of 30), remaining should be 30
    rem = remaining_seconds(period=30, timestamp=0.0)
    assert rem == 30

    # At t=29, remaining should be 1
    assert remaining_seconds(period=30, timestamp=29.0) == 1


# ── Validate TOTP ─────────────────────────────────────────────────────────────

def test_validate_totp_current_window() -> None:
    secret = b"12345678901234567890"
    ts = time.time()
    code = generate_totp(secret, digits=6, period=30, timestamp=ts)
    assert validate_totp(code, secret, digits=6, period=30, timestamp=ts)


def test_validate_totp_wrong_code() -> None:
    secret = b"12345678901234567890"
    assert not validate_totp("000000", secret, digits=6, period=30, timestamp=0.0)


# ── Validate HOTP ─────────────────────────────────────────────────────────────

def test_validate_hotp_correct() -> None:
    secret = RFC_SECRET
    new_counter = validate_hotp("755224", secret, counter=0)
    assert new_counter == 1


def test_validate_hotp_look_ahead() -> None:
    secret = RFC_SECRET
    # Token for counter=5 with counter at 0 → look-ahead to 5
    new_counter = validate_hotp("254676", secret, counter=0, look_ahead=10)
    assert new_counter == 6


def test_validate_hotp_invalid() -> None:
    result = validate_hotp("000000", RFC_SECRET, counter=0, look_ahead=5)
    assert result is None


# ── Utils ─────────────────────────────────────────────────────────────────────

def test_normalize_secret_strips_spaces() -> None:
    assert normalize_secret("JBSW Y3DP") == "JBSWY3DP"  # no padding needed here (len=8)


def test_normalize_secret_adds_padding() -> None:
    s = "JBSWY3DPEHPK3PXP"  # 16 chars — already a multiple of 8
    normalized = normalize_secret(s)
    assert "=" not in normalized or normalized.endswith("=")


def test_decode_secret_roundtrip() -> None:
    raw = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
    encoded = encode_secret(raw)
    assert decode_secret(encoded) == raw


def test_decode_secret_invalid_raises() -> None:
    with pytest.raises(ValueError):
        decode_secret("!!!NOTBASE32!!!")


def test_format_otp_6_digits() -> None:
    assert format_otp("123456") == "123 456"


def test_format_otp_8_digits() -> None:
    assert format_otp("12345678") == "123 456 78"
