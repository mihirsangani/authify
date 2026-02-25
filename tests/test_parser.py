"""Tests for authify.qr.parser."""

import pytest

from core.totp import Algorithm
from qr.parser import OTPAuthURI, build_otpauth_uri, parse_otpauth_uri


# ── Valid TOTP URIs ───────────────────────────────────────────────────────────

def test_parse_basic_totp() -> None:
    uri = "otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    result = parse_otpauth_uri(uri)
    assert result.otp_type == "totp"
    assert result.account_name == "alice@example.com"
    assert result.issuer == "Example"
    assert "JBSWY3DPEHPK3PXP" in result.secret
    assert result.algorithm == Algorithm.SHA1
    assert result.digits == 6
    assert result.period == 30


def test_parse_totp_with_sha256() -> None:
    uri = (
        "otpauth://totp/Issuer%3Auser?secret=JBSWY3DPEHPK3PXP"
        "&algorithm=SHA256&digits=8&period=60"
    )
    result = parse_otpauth_uri(uri)
    assert result.algorithm == Algorithm.SHA256
    assert result.digits == 8
    assert result.period == 60


def test_parse_totp_no_issuer_in_uri() -> None:
    uri = "otpauth://totp/myaccount?secret=JBSWY3DPEHPK3PXP"
    result = parse_otpauth_uri(uri)
    assert result.account_name == "myaccount"
    assert result.issuer == ""


def test_parse_totp_issuer_from_label() -> None:
    uri = "otpauth://totp/GitHub%3Ajohn?secret=JBSWY3DPEHPK3PXP"
    result = parse_otpauth_uri(uri)
    assert result.issuer == "GitHub"
    assert result.account_name == "john"


# ── Valid HOTP URIs ───────────────────────────────────────────────────────────

def test_parse_hotp() -> None:
    uri = "otpauth://hotp/Example%3Aeve?secret=JBSWY3DPEHPK3PXP&counter=5"
    result = parse_otpauth_uri(uri)
    assert result.otp_type == "hotp"
    assert result.counter == 5


# ── Error cases ───────────────────────────────────────────────────────────────

def test_parse_wrong_scheme() -> None:
    with pytest.raises(ValueError, match="scheme"):
        parse_otpauth_uri("http://totp/acc?secret=ABC")


def test_parse_unknown_type() -> None:
    with pytest.raises(ValueError, match="OTP type"):
        parse_otpauth_uri("otpauth://steam/acc?secret=JBSWY3DPEHPK3PXP")


def test_parse_missing_secret() -> None:
    with pytest.raises(ValueError, match="secret"):
        parse_otpauth_uri("otpauth://totp/acc")


def test_parse_invalid_algorithm() -> None:
    with pytest.raises(ValueError, match="algorithm"):
        parse_otpauth_uri("otpauth://totp/acc?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")


def test_parse_invalid_digits() -> None:
    with pytest.raises(ValueError):
        parse_otpauth_uri("otpauth://totp/acc?secret=JBSWY3DPEHPK3PXP&digits=5")


def test_parse_hotp_missing_counter() -> None:
    with pytest.raises(ValueError, match="counter"):
        parse_otpauth_uri("otpauth://hotp/acc?secret=JBSWY3DPEHPK3PXP")


# ── Builder ───────────────────────────────────────────────────────────────────

def test_build_roundtrip() -> None:
    uri = build_otpauth_uri(
        otp_type="totp",
        account_name="alice@example.com",
        secret="JBSWY3DPEHPK3PXP",
        issuer="Example",
        digits=6,
        period=30,
    )
    parsed = parse_otpauth_uri(uri)
    assert parsed.account_name == "alice@example.com"
    assert parsed.issuer == "Example"
    assert parsed.digits == 6
    assert parsed.period == 30


def test_build_hotp_uri() -> None:
    uri = build_otpauth_uri(
        otp_type="hotp",
        account_name="bob",
        secret="JBSWY3DPEHPK3PXP",
        counter=10,
    )
    assert uri.startswith("otpauth://hotp/")
    assert "counter=10" in uri
