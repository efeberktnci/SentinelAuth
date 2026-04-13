"""
OpenID-style signing helpers for the local SentinelAuth lab.

This module does not talk to a live external provider. Instead, it simulates
the callback packet structure and provider-side verification behaviors closely
enough to model identity tampering and integrity validation in a local lab.
"""
import hashlib
import hmac
import os
import secrets
import time
from urllib.parse import urlparse

from core.database import USED_OPENID_NONCES


SECRET_KEY = os.environ.get(
    "SENTINEL_SECRET",
    "s3nt1n3l_pr0d_hmac_k3y_xK9pL2mN8qR5vT7wZ",
)

OPENID_NS = "http://specs.openid.net/auth/2.0"
PROVIDER_ENDPOINT = "https://provider.local/openid/login"
SIGNED_FIELDS = [
    "op_endpoint",
    "claimed_id",
    "identity",
    "return_to",
    "response_nonce",
    "assoc_handle",
    "realm",
]


def _canonical_payload(packet: dict) -> bytes:
    lines = [f"{field}:{packet.get(f'openid.{field}', '')}" for field in SIGNED_FIELDS]
    return "\n".join(lines).encode("utf-8")


def _realm_from_return_to(return_to: str) -> str:
    parsed = urlparse(return_to)
    return f"{parsed.scheme}://{parsed.netloc}/"


def sign_openid_assertion(account_id: str, return_to: str) -> dict:
    """Create a local OpenID-style callback packet."""
    timestamp = str(int(time.time()))
    identity_url = f"{PROVIDER_ENDPOINT.rsplit('/', 1)[0]}/id/{account_id}"
    packet = {
        "openid.ns": OPENID_NS,
        "openid.mode": "id_res",
        "openid.op_endpoint": PROVIDER_ENDPOINT,
        "openid.claimed_id": identity_url,
        "openid.identity": identity_url,
        "openid.return_to": return_to,
        "openid.response_nonce": f"{timestamp}-sentinel-{secrets.token_hex(6)}",
        "openid.assoc_handle": f"sentinel-assoc-{secrets.token_hex(8)}",
        "openid.realm": _realm_from_return_to(return_to),
        "openid.signed": ",".join(SIGNED_FIELDS),
    }

    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        _canonical_payload(packet),
        hashlib.sha256,
    ).hexdigest()
    packet["openid.sig"] = f"{timestamp}:{signature}"
    return packet


def extract_account_id(claimed_id_url: str) -> str:
    """Extract the numeric account identifier from an OpenID identity URL."""
    return claimed_id_url.rstrip("/").rsplit("/", 1)[-1]


def _validate_openid_structure(args: dict, expected_return_to: str) -> tuple[bool, str]:
    required_keys = [
        "openid.claimed_id",
        "openid.identity",
        "openid.sig",
        "openid.return_to",
        "openid.response_nonce",
        "openid.assoc_handle",
        "openid.realm",
        "openid.op_endpoint",
        "openid.signed",
        "openid.mode",
        "openid.ns",
    ]
    for key in required_keys:
        if not args.get(key):
            return False, f"Missing required parameter: {key}"

    if args["openid.ns"] != OPENID_NS:
        return False, "Unexpected OpenID namespace"

    if args["openid.mode"] != "id_res":
        return False, "Unexpected OpenID mode"

    claimed_id = args["openid.claimed_id"]
    identity = args["openid.identity"]
    if claimed_id != identity:
        return False, "openid.claimed_id and openid.identity do not match"

    if args["openid.return_to"] != expected_return_to:
        return False, "openid.return_to does not match the expected callback URL"

    if args["openid.op_endpoint"] != PROVIDER_ENDPOINT:
        return False, "Unexpected provider endpoint"

    if args["openid.realm"] != _realm_from_return_to(expected_return_to):
        return False, "openid.realm does not match the expected relying-party origin"

    if args["openid.signed"] != ",".join(SIGNED_FIELDS):
        return False, "Signed field list is malformed or unexpected"

    sig_token = args["openid.sig"]
    if ":" not in sig_token:
        return False, "Malformed signature: missing timestamp separator"

    timestamp, _ = sig_token.split(":", 1)
    if not timestamp.isdigit():
        return False, "Malformed signature: timestamp is not numeric"

    token_age = abs(int(time.time()) - int(timestamp))
    if token_age > 600:
        return False, f"Token expired; age: {token_age}s (max allowed: 600s)"

    return True, "OpenID structure valid"


def provider_check_authentication(args: dict, expected_return_to: str) -> tuple[bool, str]:
    """
    Simulate an OpenID provider-side check_authentication response.

    The provider validates the assertion fields and recomputes the HMAC over
    the originally signed values. This models the consumer calling back to the
    provider to verify whether the assertion is still valid.
    """
    is_valid, reason = _validate_openid_structure(args, expected_return_to)
    if not is_valid:
        return False, reason

    sig_token = args["openid.sig"]
    _, signature = sig_token.split(":", 1)
    packet = {key: args[key] for key in args if key.startswith("openid.")}
    expected_sig = hmac.new(
        SECRET_KEY.encode("utf-8"),
        _canonical_payload(packet),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, signature):
        claimed_account_id = extract_account_id(args["openid.claimed_id"])
        return (
            False,
            f"HMAC mismatch - openid.claimed_id '{claimed_account_id}' "
            f"does not match the identity that was originally signed. "
            f"Identifier manipulation detected.",
        )

    return True, "is_valid:true"


def verify_openid_assertion(args: dict, expected_return_to: str) -> tuple[bool, str]:
    """Verify an OpenID-style callback packet in the secure flow."""
    try:
        is_valid, reason = provider_check_authentication(args, expected_return_to)
        if not is_valid:
            return False, reason

        nonce = args["openid.response_nonce"]
        if nonce in USED_OPENID_NONCES:
            return False, "Replay detected: openid.response_nonce has already been accepted"

        USED_OPENID_NONCES.add(nonce)
        return True, f"Signature valid; identity confirmed: account {extract_account_id(args['openid.claimed_id'])}"
    except Exception as exc:
        return False, f"Verification exception: {type(exc).__name__}: {exc}"
