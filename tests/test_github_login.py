from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from app.config import Settings
from app.database import Database
from app.github_client import GitHubClientError
from app.service import TrackerService


def build_settings(tmpdir: Path) -> Settings:
    data_dir = tmpdir / "data"
    reports_dir = data_dir / "reports"
    database_path = data_dir / "tracker.db"
    reports_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        bbradar_base_url="https://example.invalid",
        vigilseek_base_url="https://example.invalid",
        vigilseek_enabled=False,
        track_platforms=["HackenProof"],
        track_scope_keywords=[],
        bbradar_interval_minutes=30,
        github_interval_minutes=60,
        notification_retry_interval_minutes=5,
        digest_enabled=False,
        digest_interval_hours=24,
        backup_enabled=False,
        backup_interval_hours=24,
        sla_reminder_enabled=False,
        sla_reminder_interval_minutes=30,
        source_alert_cooldown_minutes=60,
        api_key_signing_secret="test-secret",
        job_worker_count=1,
        stale_job_timeout_minutes=120,
        housekeeping_enabled=False,
        housekeeping_interval_hours=6,
        event_retention_days=120,
        job_retention_days=30,
        database_busy_timeout_ms=5000,
        timezone="UTC",
        request_timeout_seconds=30,
        bootstrap_notify_existing=False,
        data_dir=data_dir,
        reports_dir=reports_dir,
        database_path=database_path,
        telegram_bot_token="token",
        telegram_chat_id="chat",
        github_telegram_bot_token="github-telegram-token",
        github_telegram_chat_id="github-chat",
        github_token="github-token",
        github_oauth_client_id=None,
        github_oauth_client_secret=None,
        github_oauth_redirect_uri=None,
        github_oauth_scope="read:user user:email",
        bootstrap_admin_username="owner",
        bootstrap_admin_api_key=None,
    )


class GitHubLoginServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        tmpdir = Path(self._tempdir.name)
        self.settings = build_settings(tmpdir)
        self.db = Database(self.settings.database_path, busy_timeout_ms=self.settings.database_busy_timeout_ms)
        self.service = TrackerService(settings=self.settings, db=self.db)

    def tearDown(self) -> None:
        self.service.close()
        self.db.close()
        self._tempdir.cleanup()

    def test_get_github_login_user_caches_successful_lookup(self) -> None:
        self.service._fetch_github_login_user_payload = Mock(
            return_value={
                "id": 7,
                "login": "octocat",
                "name": "The Octocat",
                "avatar_url": "https://example.invalid/octocat.png",
                "html_url": "https://github.com/octocat",
                "email": "octocat@example.invalid",
            }
        )

        first = self.service.get_github_login_user()
        second = self.service.get_github_login_user()

        self.assertEqual(first["login"], "octocat")
        self.assertEqual(second["login"], "octocat")
        self.assertEqual(first["auth_mode"], "token")
        self.service._fetch_github_login_user_payload.assert_called_once()

    def test_get_github_login_user_uses_fallback_when_lookup_fails(self) -> None:
        self.service._fetch_github_login_user_payload = Mock(
            side_effect=GitHubClientError("GitHub request failed (504): gateway timeout")
        )

        user = self.service.get_github_login_user()

        self.assertEqual(user["login"], "token-user")
        self.assertEqual(user["id"], "local-token")
        self.assertEqual(user["auth_mode"], "token_fallback")


class GitHubLoginRouteTest(unittest.TestCase):
    def test_route_redirects_with_service_login_user(self) -> None:
        from app import main as main_module

        self.addCleanup(main_module.service.close)
        self.addCleanup(main_module.db.close)

        login_user = {
            "id": 42,
            "login": "octocat",
            "name": "The Octocat",
            "avatar_url": None,
            "html_url": "https://github.com/octocat",
            "email": None,
            "auth_mode": "token",
        }

        with (
            patch.object(main_module, "_github_oauth_ready", return_value=False),
            patch.object(main_module.settings, "github_token", "github-token"),
            patch.object(main_module.service, "get_github_login_user", return_value=login_user) as login_mock,
        ):
            response = main_module.github_login(return_to="http://127.0.0.1:3001/app")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers["location"],
            "http://127.0.0.1:3001/app?github_login=octocat&github_id=42",
        )
        login_mock.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
