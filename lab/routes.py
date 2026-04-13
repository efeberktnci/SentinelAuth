"""OpenID-style local lab routes."""
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for

from core.database import (
    PLAYERS,
    find_player_by_credentials,
    log_incident,
)
from core.security import (
    extract_account_id,
    provider_check_authentication,
    sign_openid_assertion,
    verify_openid_assertion,
)


lab = Blueprint("lab", __name__, url_prefix="/lab")


def _ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")


def _current_player():
    account_id = session.get("lab_user")
    if not account_id or account_id not in PLAYERS:
        return None, redirect(url_for("lab.lab_index"))
    return PLAYERS[account_id], None


def _provider_check_url() -> str:
    return request.url_root.rstrip("/") + url_for("lab.provider_check_authentication_route")


def _post_check_authentication(payload: dict) -> tuple[bool, str]:
    """
    Simulate the relying party POSTing the assertion back to the provider.

    In runtime this uses a real HTTP POST against the local provider endpoint.
    In tests it falls back to Flask's test client so the same verification logic
    can be exercised without a live threaded server.
    """
    if current_app.testing:
        with current_app.test_client() as client:
            response = client.post("/lab/provider/check-authentication", data=payload)
            body = response.get_data(as_text=True)
    else:
        encoded = urlencode(payload).encode("utf-8")
        request_obj = Request(
            _provider_check_url(),
            data=encoded,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            # Bypass any system/Burp proxy settings for local loopback verification.
            opener = build_opener(ProxyHandler({}))
            with opener.open(request_obj, timeout=5) as response:
                body = response.read().decode("utf-8")
        except URLError as exc:
            return False, f"Provider verification request failed: {exc.reason}"
        except Exception as exc:
            return False, f"Provider verification request failed: {type(exc).__name__}: {exc}"

    if "is_valid:true" in body:
        return True, "Provider verification returned is_valid:true"

    reason = "Provider verification returned is_valid:false"
    for line in body.splitlines():
        if line.startswith("error:"):
            reason = line.split(":", 1)[1].strip()
            break
    return False, reason


@lab.route("/")
def lab_index():
    return redirect(url_for("lab.lab_login", mode="vulnerable"))


@lab.route("/login/<mode>")
def lab_login(mode):
    if mode not in ("vulnerable", "secure"):
        return redirect(url_for("lab.lab_login", mode="vulnerable"))
    return render_template("lab_login.html", mode=mode, error=None)


@lab.route("/provider/<mode>")
def provider_login(mode):
    if mode not in ("vulnerable", "secure"):
        return redirect(url_for("lab.lab_login", mode="vulnerable"))
    return render_template("provider_login.html", mode=mode, error=None)


@lab.route("/provider/authorize/<mode>", methods=["POST"])
def provider_authorize(mode):
    """Simulate the provider login and return an OpenID-style assertion."""
    if mode not in ("vulnerable", "secure"):
        return "Invalid mode", 400

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    player = find_player_by_credentials(username, password)
    if not player:
        return render_template("provider_login.html", mode=mode, error="Invalid username or password"), 401

    return_to = request.url_root.rstrip("/") + url_for(f"lab.lab_callback_{mode}")
    packet = sign_openid_assertion(player["account_id"], return_to)
    params = urlencode(
        {
            "openid.ns": packet["openid.ns"],
            "openid.mode": packet["openid.mode"],
            "openid.op_endpoint": packet["openid.op_endpoint"],
            "openid.claimed_id": packet["openid.claimed_id"],
            "openid.identity": packet["openid.identity"],
            "openid.return_to": packet["openid.return_to"],
            "openid.realm": packet["openid.realm"],
            "openid.assoc_handle": packet["openid.assoc_handle"],
            "openid.signed": packet["openid.signed"],
            "openid.sig": packet["openid.sig"],
            "openid.response_nonce": packet["openid.response_nonce"],
        }
    )
    return redirect(f"{url_for(f'lab.lab_callback_{mode}')}?{params}")


@lab.route("/provider/check-authentication", methods=["POST"])
def provider_check_authentication_route():
    """Simulate the provider-side check_authentication verification step."""
    payload = request.form.to_dict(flat=True)
    expected_return_to = payload.get("openid.return_to", "").strip()
    is_valid, reason = provider_check_authentication(payload, expected_return_to)

    response_lines = [
        "ns:http://specs.openid.net/auth/2.0",
        "is_valid:true" if is_valid else "is_valid:false",
    ]
    if not is_valid:
        response_lines.append(f"error:{reason}")
    return "\n".join(response_lines) + "\n", 200, {"Content-Type": "text/plain; charset=utf-8"}


@lab.route("/callback/vulnerable")
def lab_callback_vulnerable():
    claimed_id = request.args.get("openid.claimed_id", "")
    if not claimed_id:
        return render_template("lab_blocked.html", reason="Missing openid.claimed_id parameter"), 400

    account_id = extract_account_id(claimed_id)
    if account_id not in PLAYERS:
        return render_template("lab_blocked.html", reason=f"Account identifier {account_id} not found", account_id=account_id), 404

    session["lab_user"] = account_id
    session["lab_mode"] = "vulnerable"

    log_incident(
        event_type="LAB_IDENTITY_ACCEPTED",
        attacker_ip=_ip(),
        severity="CRITICAL",
        details={
            "endpoint": "VULNERABLE",
            "claimed_account_id": account_id,
            "username": PLAYERS[account_id]["username"],
            "note": "No provider verification; claimed identity was trusted directly.",
        },
    )
    return redirect(url_for("lab.lab_profile"))


@lab.route("/callback/secure")
def lab_callback_secure():
    claimed_id = request.args.get("openid.claimed_id", "")
    if not claimed_id:
        return render_template("lab_blocked.html", reason="Missing openid.claimed_id parameter"), 400

    expected_return_to = request.url_root.rstrip("/") + url_for("lab.lab_callback_secure")
    account_id = extract_account_id(claimed_id)
    payload = request.args.to_dict(flat=True)

    provider_valid, provider_reason = _post_check_authentication(payload)
    if not provider_valid:
        log_incident(
            event_type="LAB_SPOOFING_BLOCKED",
            attacker_ip=_ip(),
            severity="HIGH",
            details={
                "endpoint": "SECURE",
                "claimed_account_id": account_id,
                "rejection_reason": provider_reason,
                "source": "provider_check_authentication",
            },
        )
        return render_template("lab_blocked.html", reason=provider_reason, account_id=account_id), 403

    is_valid, reason = verify_openid_assertion(payload, expected_return_to)
    if not is_valid:
        log_incident(
            event_type="LAB_SPOOFING_BLOCKED",
            attacker_ip=_ip(),
            severity="HIGH",
            details={
                "endpoint": "SECURE",
                "claimed_account_id": account_id,
                "rejection_reason": reason,
                "source": "consumer_validation",
            },
        )
        return render_template("lab_blocked.html", reason=reason, account_id=account_id), 403

    if account_id not in PLAYERS:
        return render_template("lab_blocked.html", reason=f"Account identifier {account_id} not found", account_id=account_id), 404

    session["lab_user"] = account_id
    session["lab_mode"] = "secure"

    log_incident(
        event_type="LAB_LOGIN_SUCCESS",
        attacker_ip=_ip(),
        severity="INFO",
        details={
            "endpoint": "SECURE",
            "account_id": account_id,
            "username": PLAYERS[account_id]["username"],
            "provider_verification": "is_valid:true",
        },
    )
    return redirect(url_for("lab.lab_profile"))


@lab.route("/profile")
def lab_profile():
    player, redirect_response = _current_player()
    if redirect_response:
        return redirect_response

    return render_template(
        "lab_profile.html",
        player=player,
        mode=session.get("lab_mode", "unknown"),
    )


@lab.route("/profile/edit", methods=["POST"])
def lab_edit_profile():
    player, redirect_response = _current_player()
    if redirect_response:
        return redirect_response

    player["first_name"] = request.form.get("first_name", "").strip() or player["first_name"]
    player["last_name"] = request.form.get("last_name", "").strip() or player["last_name"]
    player["phone"] = request.form.get("phone", "").strip() or player["phone"]
    player["address"] = request.form.get("address", "").strip() or player["address"]
    player["country"] = request.form.get("country", "").strip() or player["country"]

    log_incident(
        event_type="PROFILE_UPDATED",
        attacker_ip=_ip(),
        severity="INFO",
        details={
            "username": player["username"],
            "fields": ["first_name", "last_name", "phone", "address", "country"],
        },
    )
    return redirect(url_for("lab.lab_profile"))


@lab.route("/profile/change-email", methods=["POST"])
def lab_change_email():
    player, redirect_response = _current_player()
    if redirect_response:
        return redirect_response

    new_email = request.form.get("email", "").strip()
    if new_email:
        player["email"] = new_email
        player["email_verified"] = False
        log_incident(
            event_type="EMAIL_CHANGED",
            attacker_ip=_ip(),
            severity="INFO",
            details={
                "username": player["username"],
                "new_email": new_email,
            },
        )
    return redirect(url_for("lab.lab_profile"))


@lab.route("/profile/change-password", methods=["POST"])
def lab_change_password():
    player, redirect_response = _current_player()
    if redirect_response:
        return redirect_response

    new_password = request.form.get("new_password", "").strip()
    if new_password:
        player["password"] = new_password
        player["security"]["password_last_changed"] = "Just now"
        log_incident(
            event_type="PASSWORD_CHANGED",
            attacker_ip=_ip(),
            severity="INFO",
            details={
                "username": player["username"],
                "note": "Password updated from account dashboard",
            },
        )
    return redirect(url_for("lab.lab_profile"))


@lab.route("/logout")
def lab_logout():
    session.pop("lab_user", None)
    session.pop("lab_mode", None)
    return redirect(url_for("lab.lab_index"))
