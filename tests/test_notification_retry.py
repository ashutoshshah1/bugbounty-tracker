from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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


def seed_program(db: Database, *, external_id: str, platform: str, name: str, source: str = "bbradar") -> None:
    raw_json = {
        "source": source,
        "external_id": external_id,
        "platform": platform,
        "handle": external_id.split(":", 1)[-1],
        "name": name,
        "link": f"https://example.invalid/{external_id}",
        "date_launched": "2026-03-01T00:00:00+00:00",
        "scope_type": "smart contract",
        "bounty_min": 1000.0,
        "bounty_max": 50000.0,
    }
    db.upsert_program(
        {
            **raw_json,
            "raw_json": raw_json,
            "data_hash": f"hash-{external_id}",
        },
        now_iso="2026-03-01T00:00:00+00:00",
    )


class NotificationRetryTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        tmpdir = Path(self._tempdir.name)
        self.settings = build_settings(tmpdir)
        self.db = Database(self.settings.database_path, busy_timeout_ms=self.settings.database_busy_timeout_ms)
        self.service = TrackerService(settings=self.settings, db=self.db)
        self.default_messages: list[str] = []
        self.github_messages: list[str] = []
        self.service.notifier.send_message = self._fake_default_send_message
        self.service.github_notifier.send_message = self._fake_github_send_message

    def tearDown(self) -> None:
        self.service.close()
        self.db.close()
        self._tempdir.cleanup()

    def _fake_default_send_message(self, text: str) -> bool:
        self.default_messages.append(text)
        return True

    def _fake_github_send_message(self, text: str) -> bool:
        self.github_messages.append(text)
        return True

    def test_retry_pending_notifications_replays_program_and_github_updates(self) -> None:
        seed_program(self.db, external_id="HackenProof:walrus", platform="HackenProof", name="Walrus")

        program_event_id = self.db.insert_event(
            event_type="program_updated",
            title="Program updated: Walrus (HackenProof)",
            details={
                "program_external_id": "HackenProof:walrus",
                "changed_fields": ["scope_type"],
                "field_diffs": {"scope_type": {"old": "smart contract", "new": "smart contract,move"}},
                "link": "https://example.invalid/walrus",
                "reward": "$1,000 - $50,000",
                "alert_suppressed": False,
                "alert_suppressed_reason": "",
            },
            created_at="2026-03-01T01:00:00+00:00",
            program_external_id="HackenProof:walrus",
            notified=False,
        )
        github_event_id = self.db.insert_event(
            event_type="github_updated",
            title="GitHub updated: MystenLabs/walrus",
            details={
                "repo_owner": "MystenLabs",
                "repo_name": "walrus",
                "file_path": "",
                "branch": "main",
                "requested_branch": "main",
                "old_sha": "1234567890abcdef",
                "new_sha": "fedcba0987654321",
                "html_url": "https://github.com/MystenLabs/walrus/commits/main",
                "changed_files": [{"filename": "contracts/staking.move", "status": "modified"}],
                "program_external_id": "HackenProof:walrus",
            },
            created_at="2026-03-01T01:05:00+00:00",
            program_external_id="HackenProof:walrus",
            notified=False,
        )

        summary = self.service.retry_pending_notifications(trigger="test")

        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["attempted"], 2)
        self.assertEqual(summary["sent"], 2)
        self.assertTrue(any("[PROGRAM UPDATED]" in item for item in self.default_messages))
        self.assertFalse(any("[GITHUB UPDATED]" in item for item in self.default_messages))
        self.assertTrue(any("[GITHUB UPDATED]" in item for item in self.github_messages))

        events = {item["id"]: item for item in self.db.list_events(limit=10)}
        self.assertEqual(events[program_event_id]["notified"], 1)
        self.assertEqual(events[github_event_id]["notified"], 1)

    def test_retry_pending_notifications_skips_suppressed_program_updates(self) -> None:
        seed_program(self.db, external_id="HackenProof:quiet", platform="HackenProof", name="Quiet")

        event_id = self.db.insert_event(
            event_type="program_updated",
            title="Program updated: Quiet (HackenProof)",
            details={
                "program_external_id": "HackenProof:quiet",
                "changed_fields": ["bounty_min"],
                "field_diffs": {"bounty_min": {"old": 0.0, "new": 1000.0}},
                "link": "https://example.invalid/quiet",
                "reward": "$0 - $10,000",
                "alert_suppressed": True,
                "alert_suppressed_reason": "noisy_immunefi_bounty_min_flip",
            },
            created_at="2026-03-01T01:00:00+00:00",
            program_external_id="HackenProof:quiet",
            notified=False,
        )

        summary = self.service.retry_pending_notifications(trigger="test")

        self.assertEqual(summary["attempted"], 0)
        self.assertEqual(summary["sent"], 0)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(self.default_messages, [])
        self.assertEqual(self.github_messages, [])

        events = {item["id"]: item for item in self.db.list_events(limit=10)}
        self.assertEqual(events[event_id]["notified"], 0)


if __name__ == "__main__":
    unittest.main()
