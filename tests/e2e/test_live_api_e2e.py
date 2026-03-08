from __future__ import annotations

import os
import unittest
from urllib.parse import parse_qs, urlparse

import requests


BASE_URL = os.getenv("E2E_BASE_URL", "http://127.0.0.1:3001").rstrip("/")
API_BASE = f"{BASE_URL}/api"
APP_URL = f"{BASE_URL}/app"
TIMEOUT_SECONDS = float(os.getenv("E2E_TIMEOUT_SECONDS", "20"))


class LiveApiE2ETest(unittest.TestCase):
    def test_live_app_health_programs_and_github_login(self) -> None:
        health_response = requests.get(f"{API_BASE}/health", timeout=TIMEOUT_SECONDS)
        self.assertEqual(health_response.status_code, 200)
        health = health_response.json()
        self.assertIn("github_token_configured", health)

        programs_response = requests.get(
            f"{API_BASE}/programs",
            params={"limit": 1},
            timeout=TIMEOUT_SECONDS,
        )
        self.assertEqual(programs_response.status_code, 200)
        programs = programs_response.json()
        self.assertIsInstance(programs, list)
        self.assertGreaterEqual(len(programs), 1)

        app_response = requests.get(APP_URL, timeout=TIMEOUT_SECONDS)
        self.assertEqual(app_response.status_code, 200)
        self.assertIn("GitHub Login", app_response.text)

        login_response = requests.get(
            f"{API_BASE}/auth/github/login",
            params={"return_to": APP_URL},
            allow_redirects=False,
            timeout=TIMEOUT_SECONDS,
        )
        self.assertEqual(login_response.status_code, 302)

        redirect_url = login_response.headers.get("location", "")
        self.assertTrue(redirect_url)

        if health.get("github_oauth_configured"):
            self.assertTrue(redirect_url.startswith("https://github.com/login/oauth/authorize?"))
            return

        self.assertTrue(health.get("github_token_configured"))
        self.assertTrue(redirect_url.startswith(APP_URL))

        parsed_redirect = urlparse(redirect_url)
        params = parse_qs(parsed_redirect.query)
        self.assertTrue(params.get("github_login"))
        self.assertTrue(params.get("github_id"))


if __name__ == "__main__":
    unittest.main()
