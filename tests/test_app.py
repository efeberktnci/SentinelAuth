import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlparse

from core.database import reset_runtime_state, restore_player
from run import create_app


class SentinelAuthTests(unittest.TestCase):
    def setUp(self):
        restore_player("76561198123456789")
        restore_player("76561198987654321")
        reset_runtime_state()
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()

    def test_home_page_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("SentinelAuth", response.get_data(as_text=True))

    def test_consumer_login_uses_provider_style_entry(self):
        response = self.client.get("/lab/login/vulnerable")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("Continue to Provider", body)
        self.assertIn("/lab/provider/vulnerable", body)

    def test_players_endpoint_matches_neutral_schema(self):
        response = self.client.get("/api/players")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("players", payload)
        self.assertGreaterEqual(len(payload["players"]), 2)
        first_player = payload["players"][0]
        self.assertIn("email", first_player)
        self.assertIn("role", first_player)
        self.assertIn("plan", first_player)
        self.assertNotIn("level", first_player)

    def test_provider_check_authentication_returns_true_for_original_packet(self):
        login_response = self.client.post(
            "/lab/provider/authorize/secure",
            data={"username": "attacker", "password": "attacker123"},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        parsed = urlparse(login_response.headers["Location"])
        query = parse_qs(parsed.query, keep_blank_values=True)
        payload = {key: values[0] for key, values in query.items()}

        verify_response = self.client.post("/lab/provider/check-authentication", data=payload)
        body = verify_response.get_data(as_text=True)
        self.assertEqual(verify_response.status_code, 200)
        self.assertIn("is_valid:true", body)

    def test_vulnerable_callback_accepts_tampered_identity(self):
        login_response = self.client.post(
            "/lab/provider/authorize/vulnerable",
            data={"username": "attacker", "password": "attacker123"},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        location = login_response.headers["Location"]
        tampered_location = location.replace("76561198987654321", "76561198123456789")
        response = self.client.get(tampered_location, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("operator@sentynelauth.local", response.get_data(as_text=True))

    def test_secure_callback_calls_provider_verification(self):
        login_response = self.client.post(
            "/lab/provider/authorize/secure",
            data={"username": "attacker", "password": "attacker123"},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch("lab.routes._post_check_authentication", return_value=(True, "Provider verification returned is_valid:true")) as mocked:
            response = self.client.get(login_response.headers["Location"], follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        mocked.assert_called_once()

    def test_secure_callback_blocks_tampered_identity(self):
        login_response = self.client.post(
            "/lab/provider/authorize/secure",
            data={"username": "attacker", "password": "attacker123"},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        location = login_response.headers["Location"]
        tampered_location = location.replace("76561198987654321", "76561198123456789")
        response = self.client.get(tampered_location, follow_redirects=False)

        self.assertEqual(response.status_code, 403)
        self.assertIn("Access Denied", response.get_data(as_text=True))

    def test_secure_callback_blocks_claimed_id_identity_mismatch(self):
        login_response = self.client.post(
            "/lab/provider/authorize/secure",
            data={"username": "attacker", "password": "attacker123"},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        parsed = urlparse(login_response.headers["Location"])
        query = parse_qs(parsed.query, keep_blank_values=True)
        query["openid.claimed_id"] = ["https://provider.local/openid/id/76561198123456789"]
        tampered_query = urlencode({key: values[0] for key, values in query.items()})
        response = self.client.get(f"{parsed.path}?{tampered_query}", follow_redirects=False)

        self.assertEqual(response.status_code, 403)
        self.assertIn("openid.claimed_id and openid.identity do not match", response.get_data(as_text=True))

    def test_secure_callback_blocks_replay_of_same_nonce(self):
        login_response = self.client.post(
            "/lab/provider/authorize/secure",
            data={"username": "attacker", "password": "attacker123"},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        callback_path = login_response.headers["Location"]
        first_response = self.client.get(callback_path, follow_redirects=False)
        second_response = self.client.get(callback_path, follow_redirects=False)

        self.assertEqual(first_response.status_code, 302)
        self.assertEqual(second_response.status_code, 403)
        self.assertIn("Replay detected", second_response.get_data(as_text=True))

    def test_profile_actions_update_account(self):
        with self.client.session_transaction() as session:
            session["lab_user"] = "76561198123456789"
            session["lab_mode"] = "vulnerable"

        edit_response = self.client.post(
            "/lab/profile/edit",
            data={
                "first_name": "Efe",
                "last_name": "Berke",
                "phone": "+90 555 444 3322",
                "country": "TR",
                "address": "Istanbul",
            },
            follow_redirects=True,
        )
        self.assertEqual(edit_response.status_code, 200)
        self.assertIn("+90 555 444 3322", edit_response.get_data(as_text=True))

        email_response = self.client.post(
            "/lab/profile/change-email",
            data={"email": "updated@sentynelauth.local"},
            follow_redirects=True,
        )
        self.assertEqual(email_response.status_code, 200)
        self.assertIn("updated@sentynelauth.local", email_response.get_data(as_text=True))

        password_response = self.client.post(
            "/lab/profile/change-password",
            data={"new_password": "stronger-password-1"},
            follow_redirects=True,
        )
        self.assertEqual(password_response.status_code, 200)
        self.assertIn("Just now", password_response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
