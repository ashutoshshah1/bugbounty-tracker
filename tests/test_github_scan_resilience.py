from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

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
        request_timeout_seconds=1,
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


class GitHubScanResilienceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        tmpdir = Path(self._tempdir.name)
        self.settings = build_settings(tmpdir)
        self.db = Database(self.settings.database_path, busy_timeout_ms=self.settings.database_busy_timeout_ms)
        self.service = TrackerService(settings=self.settings, db=self.db)
        self.messages: list[str] = []
        self.service.notifier.send_message = self._fake_send_message

    def tearDown(self) -> None:
        self.service.close()
        self.db.close()
        self._tempdir.cleanup()

    def _fake_send_message(self, text: str) -> bool:
        self.messages.append(text)
        return True

    def _add_watch(
        self,
        *,
        owner: str = "missing-owner",
        repo: str = "missing-repo",
        file_path: str = "",
        branch: str = "main",
    ) -> dict:
        return self.db.add_github_watch(
            program_external_id=None,
            repo_owner=owner,
            repo_name=repo,
            file_path=file_path,
            branch=branch,
            metadata={"source": "test"},
            now_iso="2026-03-01T00:00:00+00:00",
        )

    def test_not_found_watch_error_does_not_emit_github_source_health_alert(self) -> None:
        self._add_watch()
        self.service.github_client.fetch_target_state = Mock(
            side_effect=GitHubClientError(
                "GitHub request failed (404): Not Found",
                status_code=404,
                api_message="Not Found",
            )
        )

        summary = self.service.scan_github(trigger="test")

        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["errors"], 1)
        self.assertIsNone(self.db.get_state("source_health_alert:github"))
        self.assertFalse(any("[SOURCE HEALTH ALERT]" in item for item in self.messages))

        errors = self.db.list_events(limit=10, event_type="run_error")
        self.assertTrue(any(item["title"] == "GitHub watch check failed" for item in errors))

    def test_transient_github_error_still_emits_source_health_alert(self) -> None:
        self._add_watch()
        self.service.github_client.fetch_target_state = Mock(
            side_effect=GitHubClientError(
                "GitHub request failed (500): internal server error",
                status_code=500,
                api_message="internal server error",
            )
        )

        summary = self.service.scan_github(trigger="test")

        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["errors"], 1)
        source_state = self.db.get_state("source_health_alert:github")
        self.assertIsNotNone(source_state)
        self.assertIn("500", str(source_state.get("last_error")))
        self.assertTrue(any("[SOURCE HEALTH ALERT]" in item for item in self.messages))

    def test_transient_github_error_with_successes_does_not_emit_source_health_alert(self) -> None:
        self._add_watch(owner="example", repo="timeout-repo")
        self._add_watch(owner="example", repo="healthy-repo")
        self.service.github_client.fetch_target_state = Mock(
            side_effect=[
                GitHubClientError("GitHub request failed: connect timeout"),
                {
                    "sha": "healthy-sha",
                    "html_url": "https://github.com/example/healthy-repo/commits/main",
                    "kind": "branch",
                },
            ]
        )

        summary = self.service.scan_github(trigger="test")

        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["errors"], 1)
        self.assertEqual(summary["baseline"], 1)
        self.assertEqual(summary["source_health_error_count"], 1)
        self.assertFalse(summary["source_health_alerted"])
        self.assertIsNone(self.db.get_state("source_health_alert:github"))
        self.assertFalse(any("[SOURCE HEALTH ALERT]" in item for item in self.messages))

    def test_scan_persists_resolved_default_branch(self) -> None:
        self._add_watch(owner="example", repo="master-repo", branch="main")
        self.service.github_client.fetch_target_state = Mock(
            return_value={
                "sha": "master-sha",
                "html_url": "https://github.com/example/master-repo/commits/master",
                "kind": "branch",
                "resolved_branch": "master",
                "requested_branch": "main",
            }
        )

        summary = self.service.scan_github(trigger="test")

        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["baseline"], 1)
        watches = self.db.list_github_watches(active_only=True)
        self.assertEqual(watches[0]["branch"], "master")


if __name__ == "__main__":
    unittest.main()
