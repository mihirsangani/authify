"""
Parse otpauth:// URIs as defined by the Google Authenticator Key URI Format.

Reference: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
"""

import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from core.totp import Algorithm
from core.utils import normalize_secret, sanitise_label, validate_digits, validate_period


@dataclass
class OTPAuthURI:
    """Parsed representation of an otpauth:// URI."""

    otp_type: str       # "totp" or "hotp"
    label: str          # full label (issuer:account or just account)
    secret: str         # normalised base32 secret
    issuer: str         # issuer parameter (may be empty)
    account_name: str   # account name extracted from label
    algorithm: Algorithm
    digits: int
    period: int          # TOTP period (ignored for HOTP)
    counter: int         # HOTP counter (ignored for TOTP)


def parse_otpauth_uri(uri: str) -> OTPAuthURI:
    """
    Parse and validate an ``otpauth://`` URI.

    Args:
        uri: Full otpauth URI string.

    Returns:
        Populated :class:`OTPAuthURI` dataclass.

    Raises:
        ValueError: If the URI is malformed or contains invalid values.
    """
    uri = uri.strip()

    parsed = urllib.parse.urlparse(uri)

    if parsed.scheme.lower() != "otpauth":
        raise ValueError(f"Expected 'otpauth' scheme, got '{parsed.scheme}'.")

    otp_type = parsed.netloc.lower()
    if otp_type not in ("totp", "hotp"):
        raise ValueError(f"Unknown OTP type '{otp_type}'. Expected totp or hotp.")

    # Label is the path component (strip leading slash)
    raw_label = urllib.parse.unquote(parsed.path.lstrip("/"))
    if not raw_label:
        raise ValueError("Missing label in otpauth URI.")

    # Extract issuer and account from label  "Issuer:AccountName"
    if ":" in raw_label:
        label_issuer, account_name = raw_label.split(":", 1)
        label_issuer = sanitise_label(label_issuer.strip())
    else:
        label_issuer = ""
        account_name = raw_label

    account_name = sanitise_label(account_name.strip())

    # Query parameters
    params = dict(urllib.parse.parse_qsl(parsed.query))

    # Secret (required)
    raw_secret = params.get("secret", "")
    if not raw_secret:
        raise ValueError("Missing 'secret' parameter in otpauth URI.")
    secret = normalize_secret(raw_secret)

    # Issuer – prefer the query param; fall back to label prefix
    issuer = sanitise_label(params.get("issuer", label_issuer).strip())

    # Algorithm
    alg_str = params.get("algorithm", "SHA1").upper()
    try:
        algorithm = Algorithm(alg_str)
    except ValueError:
        raise ValueError(
            f"Unsupported algorithm '{alg_str}'. Supported: SHA1, SHA256, SHA512."
        )

    # Digits
    try:
        digits = int(params.get("digits", 6))
    except ValueError:
        raise ValueError("'digits' must be an integer.")
    validate_digits(digits)

    # Period (TOTP) / Counter (HOTP)
    period = 30
    counter = 0

    if otp_type == "totp":
        try:
            period = int(params.get("period", 30))
        except ValueError:
            raise ValueError("'period' must be an integer.")
        validate_period(period)
    else:
        raw_counter = params.get("counter")
        if raw_counter is None:
            raise ValueError("HOTP URI requires a 'counter' parameter.")
        try:
            counter = int(raw_counter)
        except ValueError:
            raise ValueError("'counter' must be an integer.")
        if counter < 0:
            raise ValueError("'counter' must be non-negative.")

    full_label = f"{issuer}:{account_name}" if issuer else account_name

    return OTPAuthURI(
        otp_type=otp_type,
        label=full_label,
        secret=secret,
        issuer=issuer,
        account_name=account_name,
        algorithm=algorithm,
        digits=digits,
        period=period,
        counter=counter,
    )


def build_otpauth_uri(
    otp_type: str,
    account_name: str,
    secret: str,
    issuer: str = "",
    algorithm: Algorithm = Algorithm.SHA1,
    digits: int = 6,
    period: int = 30,
    counter: int = 0,
) -> str:
    """Build an otpauth:// URI from individual parameters."""
    label = f"{issuer}:{account_name}" if issuer else account_name
    params: dict = {
        "secret": secret.upper().replace("=", ""),
        "algorithm": algorithm.value,
        "digits": str(digits),
    }
    if issuer:
        params["issuer"] = issuer
    if otp_type == "totp":
        params["period"] = str(period)
    else:
        params["counter"] = str(counter)

    query = urllib.parse.urlencode(params)
    label_encoded = urllib.parse.quote(label, safe="")
    return f"otpauth://{otp_type}/{label_encoded}?{query}"
