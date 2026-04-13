"""
Mock account database for identity tampering simulations.

Includes two pre-seeded accounts: a standard account and a higher-value target account.
All mutations operate on in-memory copies of the initial data.
"""
import copy
import secrets
import time
from datetime import datetime, timezone


_INITIAL_PLAYERS: dict = {
    "76561198123456789": {
        "account_id": "76561198123456789",
        "username": "operator",
        "password": "operator123",
        "first_name": "Efe",
        "last_name": "Berke",
        "email": "operator@sentynelauth.local",
        "role": "Account Owner",
        "status": "ACTIVE",
        "email_verified": True,
        "two_factor_enabled": True,
        "last_login": "2026-04-13 13:48 UTC",
        "country": "TR",
        "plan": "Enterprise",
        "phone": "+90 555 010 2000",
        "address": "Istanbul, Turkey",
        "preferences": {
            "language": "English",
            "timezone": "Europe/Istanbul",
            "marketing_opt_in": False,
        },
        "security": {
            "password_last_changed": "2026-03-28",
            "recovery_email": "security@sentynelauth.local",
            "recent_device": "Chrome on Windows",
        },
    },
    "76561198987654321": {
        "account_id": "76561198987654321",
        "username": "attacker",
        "password": "attacker123",
        "first_name": "Arda",
        "last_name": "Yilmaz",
        "email": "attacker@sentynelauth.local",
        "role": "Standard User",
        "status": "ACTIVE",
        "email_verified": False,
        "two_factor_enabled": False,
        "last_login": "2026-04-12 22:11 UTC",
        "country": "TR",
        "plan": "Basic",
        "phone": "+90 555 010 1000",
        "address": "Ankara, Turkey",
        "preferences": {
            "language": "English",
            "timezone": "Europe/Istanbul",
            "marketing_opt_in": True,
        },
        "security": {
            "password_last_changed": "2026-02-14",
            "recovery_email": "attacker-recovery@sentynelauth.local",
            "recent_device": "Chrome on Windows",
        },
    },
}


PLAYERS: dict = copy.deepcopy(_INITIAL_PLAYERS)
SESSIONS: dict = {}
INCIDENT_LOG: list = []
USED_OPENID_NONCES: set = set()


def find_player_by_credentials(username: str, password: str) -> dict | None:
    """Return an account that matches the provided lab credentials."""
    for player in PLAYERS.values():
        if player["username"] == username and player["password"] == password:
            return player
    return None


def create_session(account_id: str, endpoint: str) -> str:
    """Issue a new session token for the given account identifier."""
    token = secrets.token_hex(32)
    SESSIONS[token] = {
        "account_id": account_id,
        "username": PLAYERS.get(account_id, {}).get("username", "Unknown"),
        "created_at": int(time.time()),
        "endpoint": endpoint,
    }
    return token


def get_session(token: str) -> dict | None:
    """Return session dict or None if missing/expired (1-hour TTL)."""
    sess = SESSIONS.get(token)
    if not sess:
        return None
    if time.time() - sess["created_at"] > 3600:
        del SESSIONS[token]
        return None
    return sess


def log_incident(
    event_type: str,
    attacker_ip: str,
    details: dict,
    severity: str = "HIGH",
) -> None:
    """Prepend a security event to the incident log."""
    INCIDENT_LOG.insert(
        0,
        {
            "id": len(INCIDENT_LOG) + 1,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "unix_ts": int(time.time()),
            "event_type": event_type,
            "attacker_ip": attacker_ip,
            "severity": severity,
            "details": details,
        },
    )
    if len(INCIDENT_LOG) > 100:
        INCIDENT_LOG.pop()


def reset_player(account_id: str) -> bool:
    """Simulate destructive profile reset after account takeover."""
    if account_id not in PLAYERS:
        return False
    p = PLAYERS[account_id]
    p["email"] = f"locked-{account_id[-4:]}@sentynelauth.local"
    p["phone"] = "REMOVED"
    p["address"] = "REMOVED"
    p["status"] = "LOCKED"
    p["two_factor_enabled"] = False
    p["email_verified"] = False
    p["preferences"] = {
        "language": "Unknown",
        "timezone": "UTC",
        "marketing_opt_in": False,
    }
    p["security"]["password_last_changed"] = "RESET REQUIRED"
    p["security"]["recovery_email"] = "REMOVED"
    p["security"]["recent_device"] = "Unknown"
    return True


def restore_player(account_id: str) -> bool:
    """Restore an account to the original seed data."""
    if account_id not in _INITIAL_PLAYERS:
        return False
    PLAYERS[account_id] = copy.deepcopy(_INITIAL_PLAYERS[account_id])
    return True


def reset_runtime_state() -> None:
    """Clear runtime-only state between tests or local demo resets."""
    SESSIONS.clear()
    INCIDENT_LOG.clear()
    USED_OPENID_NONCES.clear()
