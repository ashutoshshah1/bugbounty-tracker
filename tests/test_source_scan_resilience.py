from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from requests.exceptions import ReadTimeout

from app.bbradar_client import BBRadarClientError
from app.config import Settings
from app.database import Database
from app.service import TrackerService


def build_settings(tmpdir: Path) -> Settings:
    data_dir = tmpdir / "data"
    reports_dir = data_dir / "reports"
    database_path = data_dir / "tracker.db"
    reports_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        bbradar_base_url="https://example.invalid",
        vigilseek_base_url="https://example.invalid",
        vigilseek_enabled=True,
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


class SourceScanResilienceTest(unittest.TestCase):
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

    def test_scan_continues_when_bbradar_fails_but_vigilseek_succeeds(self) -> None:
        self.service.bbradar_client.fetch_programs = Mock(
            side_effect=BBRadarClientError("frontend-token request failed with status 500")
        )
        assert self.service.vigilseek_client is not None
        self.service.vigilseek_client.fetch_programs = Mock(
            return_value=[
                {
                    "id": "w3bb-HackenProof-walrus",
                    "platform": "HackenProof",
                    "project": "Walrus",
                    "slug": "walrus",
                    "originalUrl": "https://example.invalid/walrus",
                    "startDate": "2026-03-01T00:00:00.000Z",
                    "maxReward": 50000,
                }
            ]
        )

        summary = self.service.scan_bbradar(trigger="test")

        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["tracked_programs"], 1)
        self.assertEqual(summary["created"], 1)
        self.assertEqual(summary["failed_sources"], ["bbradar"])
        self.assertIn("status 500", summary["source_errors"]["bbradar"])
        self.assertTrue(any("[SOURCE HEALTH ALERT]" in item for item in self.messages))

        programs = self.db.list_programs(limit=10, focus="all")
        self.assertEqual(len(programs), 1)
        self.assertEqual(programs[0]["external_id"], "HackenProof:walrus")
        self.assertEqual(programs[0]["source"], "vigilseek")

        errors = self.db.list_events(limit=10, event_type="run_error")
        self.assertTrue(any(item["title"] == "bbradar scan failed" for item in errors))
        source_state = self.db.get_state("source_health_alert:bbradar")
        self.assertIsNotNone(source_state)
        self.assertIn("status 500", str(source_state.get("last_error")))

    def test_scan_records_vigilseek_timeout_without_failing_job(self) -> None:
        self.service.bbradar_client.fetch_programs = Mock(
            return_value=[
                {
                    "platform": "HackenProof",
                    "handle": "walrus",
                    "name": "Walrus",
                    "link": "https://example.invalid/walrus",
                    "date_launched": "2026-03-01",
                    "bounty_max": 50000,
                }
            ]
        )
        assert self.service.vigilseek_client is not None
        self.service.vigilseek_client.fetch_programs = Mock(
            side_effect=ReadTimeout("read timeout=30")
        )

        summary = self.service.scan_bbradar(trigger="test")

        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["tracked_programs"], 1)
        self.assertEqual(summary["created"], 1)
        self.assertEqual(summary["failed_sources"], ["vigilseek"])
        self.assertIn("read timeout", summary["source_errors"]["vigilseek"])

        errors = self.db.list_events(limit=10, event_type="run_error")
        self.assertTrue(any(item["title"] == "vigilseek scan failed" for item in errors))
        source_state = self.db.get_state("source_health_alert:vigilseek")
        self.assertIsNotNone(source_state)
        self.assertIn("read timeout", str(source_state.get("last_error")))

    def test_scan_uses_cached_vigilseek_rows_when_vigilseek_times_out(self) -> None:
        cached_program = self.service._normalize_program(
            {
                "id": "w3bb-HackenProof-cached",
                "platform": "HackenProof",
                "project": "Cached Program",
                "slug": "cached",
                "originalUrl": "https://example.invalid/cached",
                "startDate": "2026-02-01T00:00:00.000Z",
                "maxReward": 10000,
            },
            source="vigilseek",
        )
        self.db.upsert_program(cached_program, "2026-02-01T00:00:00+00:00")

        self.service.bbradar_client.fetch_programs = Mock(
            return_value=[
                {
                    "platform": "HackenProof",
                    "handle": "walrus",
                    "name": "Walrus",
                    "link": "https://example.invalid/walrus",
                    "date_launched": "2026-03-01",
                    "bounty_max": 50000,
                }
            ]
        )
        assert self.service.vigilseek_client is not None
        self.service.vigilseek_client.fetch_programs = Mock(
            side_effect=ReadTimeout("read timeout=30")
        )

        summary = self.service.scan_bbradar(trigger="test")

        self.assertEqual(summary["status"], "ok")
        self.assertNotIn("failed_sources", summary)
        self.assertEqual(summary["cached_source_fallbacks"]["vigilseek"]["cached_programs"], 1)
        self.assertIn("read timeout", summary["cached_source_fallbacks"]["vigilseek"]["error"])
        self.assertFalse(any("[SOURCE HEALTH ALERT]" in item for item in self.messages))

        errors = self.db.list_events(limit=10, event_type="run_error")
        self.assertFalse(any(item["title"] == "vigilseek scan failed" for item in errors))


if __name__ == "__main__":
    unittest.main()
