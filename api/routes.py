"""
SentinelAuth API routes.

These endpoints support the local identity-tampering study and expose
JSON representations of the vulnerable and secure callback behaviors.
"""
from flask import Blueprint, jsonify, request

from core.database import (
    INCIDENT_LOG,
    PLAYERS,
    create_session,
    get_session,
    log_incident,
    reset_player,
    restore_player,
)
from core.security import (
    extract_account_id,
    provider_check_authentication,
    sign_openid_assertion,
    verify_openid_assertion,
)


api = Blueprint("api", __name__, url_prefix="/api")


def _get_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")


@api.route("/auth/init", methods=["POST"])
def auth_init():
    """Generate a signed callback packet for a seeded local account."""
    data = request.get_json(force=True, silent=True) or {}
    account_id = str(data.get("account_id", "")).strip()
    return_to = str(data.get("return_to", "http://127.0.0.1:5000/lab/callback/secure")).strip()

    if not account_id or not account_id.isdigit() or len(account_id) != 17:
        return jsonify({"error": "Invalid account identifier. Expected exactly 17 digits."}), 400
    if account_id not in PLAYERS:
        return jsonify({"error": f"Account identifier {account_id} not found in local account store"}), 404

    packet = sign_openid_assertion(account_id, return_to)
    return jsonify(
        {
            "status": "intercepted",
            "message": f"Signed callback generated for account '{PLAYERS[account_id]['username']}'.",
            "packet": packet,
        }
    )


@api.route("/auth/callback/vulnerable", methods=["POST"])
def auth_callback_vulnerable():
    """Accept the claimed identity without validating the signature."""
    data = request.get_json(force=True, silent=True) or {}
    claimed_id = data.get("openid.claimed_id", "").strip()

    if not claimed_id:
        return jsonify({"error": "Missing openid.claimed_id parameter"}), 400

    account_id = extract_account_id(claimed_id)
    if account_id not in PLAYERS:
        return jsonify({"error": f"Account {account_id} not found"}), 404

    player = PLAYERS[account_id]
    session_token = create_session(account_id, "vulnerable")
    log_incident(
        event_type="IDENTITY_SPOOFING_SUCCESS",
        attacker_ip=_get_ip(),
        severity="CRITICAL",
        details={
            "endpoint": "VULNERABLE",
            "claimed_account_id": account_id,
            "username_accessed": player["username"],
            "note": "Claimed identity accepted without provider verification.",
            "session_token": session_token[:16] + "...",
        },
    )

    return jsonify(
        {
            "status": "ACCESS_GRANTED",
            "endpoint": "VULNERABLE",
            "warning": "No provider verification was performed.",
            "session_token": session_token,
            "player": player,
        }
    )


@api.route("/auth/callback/secure", methods=["POST"])
def auth_callback_secure():
    """Validate the signature before accepting the claimed identity."""
    data = request.get_json(force=True, silent=True) or {}
    claimed_id = data.get("openid.claimed_id", "").strip()

    if not claimed_id:
        return jsonify({"error": "Missing openid.claimed_id parameter"}), 400

    expected_return_to = data.get("openid.return_to", "").strip()
    account_id = extract_account_id(claimed_id)
    is_valid, reason = verify_openid_assertion(data, expected_return_to)
    if not is_valid:
        log_incident(
            event_type="IDENTITY_SPOOFING_BLOCKED",
            attacker_ip=_get_ip(),
            severity="HIGH",
            details={
                "endpoint": "SECURE",
                "claimed_account_id": account_id,
                "rejection_reason": reason,
            },
        )
        return jsonify({"status": "ACCESS_DENIED", "endpoint": "SECURE", "reason": reason}), 403

    if account_id not in PLAYERS:
        return jsonify({"error": f"Account {account_id} not found"}), 404

    player = PLAYERS[account_id]
    session_token = create_session(account_id, "secure")
    log_incident(
        event_type="LOGIN_SUCCESS",
        attacker_ip=_get_ip(),
        severity="INFO",
        details={
            "endpoint": "SECURE",
            "account_id": account_id,
            "username": player["username"],
        },
    )
    return jsonify(
        {
            "status": "ACCESS_GRANTED",
            "endpoint": "SECURE",
            "session_token": session_token,
            "player": player,
        }
    )


@api.route("/auth/check-authentication", methods=["POST"])
def auth_check_authentication():
    """Expose the provider-side assertion validation response as JSON."""
    data = request.get_json(force=True, silent=True) or {}
    expected_return_to = data.get("openid.return_to", "").strip()
    is_valid, reason = provider_check_authentication(data, expected_return_to)
    return jsonify({"is_valid": is_valid, "reason": reason})


@api.route("/profile/<account_id>", methods=["GET"])
def get_profile(account_id: str):
    if account_id not in PLAYERS:
        return jsonify({"error": "Account not found"}), 404
    return jsonify(PLAYERS[account_id])


@api.route("/profile/reset", methods=["POST"])
def profile_reset():
    """Simulate destructive account changes after a takeover."""
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("session_token", "").strip()
    sess = get_session(token)
    if not sess:
        return jsonify({"error": "Invalid or expired session token"}), 401

    account_id = sess["account_id"]
    reset_player(account_id)
    log_incident(
        event_type="ACCOUNT_DAMAGE_EXECUTED",
        attacker_ip=_get_ip(),
        severity="CRITICAL",
        details={
            "endpoint": "VULNERABLE",
            "target_account_id": account_id,
            "target_username": PLAYERS[account_id]["username"],
            "action": "Sensitive account data reset via hijacked session",
        },
    )
    return jsonify({"status": "ACCOUNT_UPDATED", "player": PLAYERS[account_id]})


@api.route("/profile/restore", methods=["POST"])
def profile_restore():
    data = request.get_json(force=True, silent=True) or {}
    account_id = data.get("account_id", "").strip()
    if not restore_player(account_id):
        return jsonify({"error": "Account not found or cannot be restored"}), 404
    return jsonify({"status": "RESTORED", "player": PLAYERS[account_id]})


@api.route("/security/log", methods=["GET"])
def security_log():
    limit = min(int(request.args.get("limit", 50)), 100)
    return jsonify({"incidents": INCIDENT_LOG[:limit]})


@api.route("/security/log", methods=["DELETE"])
def clear_log():
    INCIDENT_LOG.clear()
    return jsonify({"status": "Log cleared", "count": 0})


@api.route("/players", methods=["GET"])
def list_players():
    return jsonify(
        {
            "players": [
                {
                    "account_id": p["account_id"],
                    "username": p["username"],
                    "email": p["email"],
                    "role": p["role"],
                    "plan": p["plan"],
                    "status": p["status"],
                    "two_factor_enabled": p["two_factor_enabled"],
                }
                for p in PLAYERS.values()
            ]
        }
    )
