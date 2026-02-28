from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _split_csv(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _to_bool(raw: str | None, default: bool) -> bool:
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "y", "on"}:
        return True
    if value in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _to_int(raw: str | None, default: int) -> int:
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(slots=True)
class Settings:
    bbradar_base_url: str
    vigilseek_base_url: str
    vigilseek_enabled: bool
    track_platforms: list[str]
    track_scope_keywords: list[str]
    bbradar_interval_minutes: int
    github_interval_minutes: int
    digest_enabled: bool
    digest_interval_hours: int
    backup_enabled: bool
    backup_interval_hours: int
    sla_reminder_enabled: bool
    sla_reminder_interval_minutes: int
    source_alert_cooldown_minutes: int
    api_key_signing_secret: str
    job_worker_count: int
    stale_job_timeout_minutes: int
    housekeeping_enabled: bool
    housekeeping_interval_hours: int
    event_retention_days: int
    job_retention_days: int
    database_busy_timeout_ms: int
    timezone: str
    request_timeout_seconds: int
    bootstrap_notify_existing: bool
    data_dir: Path
    reports_dir: Path
    database_path: Path
    telegram_bot_token: str | None
    telegram_chat_id: str | None
    github_token: str | None
    github_oauth_client_id: str | None
    github_oauth_client_secret: str | None
    github_oauth_redirect_uri: str | None
    github_oauth_scope: str
    bootstrap_admin_username: str
    bootstrap_admin_api_key: str | None

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(override=False)

        data_dir = Path(os.getenv("DATA_DIR", "data")).expanduser().resolve()
        reports_dir = Path(os.getenv("REPORTS_DIR", str(data_dir / "reports"))).expanduser().resolve()
        database_path = Path(os.getenv("DATABASE_PATH", str(data_dir / "tracker.db"))).expanduser().resolve()

        data_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)
        database_path.parent.mkdir(parents=True, exist_ok=True)

        return cls(
            bbradar_base_url=os.getenv("BBRADAR_BASE_URL", "https://bbradar.io").rstrip("/"),
            vigilseek_base_url=os.getenv("VIGILSEEK_BASE_URL", "https://new-api.vigilseek.com").rstrip("/"),
            vigilseek_enabled=_to_bool(os.getenv("VIGILSEEK_ENABLED"), True),
            track_platforms=_split_csv(os.getenv("TRACK_PLATFORMS", "HackenProof")),
            track_scope_keywords=[word.casefold() for word in _split_csv(os.getenv("TRACK_SCOPE_KEYWORDS", ""))],
            bbradar_interval_minutes=max(1, _to_int(os.getenv("BBRADAR_INTERVAL_MINUTES"), 30)),
            github_interval_minutes=max(1, _to_int(os.getenv("GITHUB_INTERVAL_MINUTES"), 60)),
            digest_enabled=_to_bool(os.getenv("DIGEST_ENABLED"), True),
            digest_interval_hours=max(1, _to_int(os.getenv("DIGEST_INTERVAL_HOURS"), 24)),
            backup_enabled=_to_bool(os.getenv("BACKUP_ENABLED"), True),
            backup_interval_hours=max(1, _to_int(os.getenv("BACKUP_INTERVAL_HOURS"), 24)),
            sla_reminder_enabled=_to_bool(os.getenv("SLA_REMINDER_ENABLED"), True),
            sla_reminder_interval_minutes=max(1, _to_int(os.getenv("SLA_REMINDER_INTERVAL_MINUTES"), 30)),
            source_alert_cooldown_minutes=max(5, _to_int(os.getenv("SOURCE_ALERT_COOLDOWN_MINUTES"), 60)),
            api_key_signing_secret=(
                os.getenv("API_KEY_SIGNING_SECRET", "local-dev-signing-secret").strip() or "local-dev-signing-secret"
            ),
            job_worker_count=max(1, _to_int(os.getenv("JOB_WORKER_COUNT"), 4)),
            stale_job_timeout_minutes=max(5, _to_int(os.getenv("STALE_JOB_TIMEOUT_MINUTES"), 120)),
            housekeeping_enabled=_to_bool(os.getenv("HOUSEKEEPING_ENABLED"), True),
            housekeeping_interval_hours=max(1, _to_int(os.getenv("HOUSEKEEPING_INTERVAL_HOURS"), 6)),
            event_retention_days=max(7, _to_int(os.getenv("EVENT_RETENTION_DAYS"), 120)),
            job_retention_days=max(3, _to_int(os.getenv("JOB_RETENTION_DAYS"), 30)),
            database_busy_timeout_ms=max(1000, _to_int(os.getenv("DATABASE_BUSY_TIMEOUT_MS"), 5000)),
            timezone=os.getenv("TIMEZONE", "UTC"),
            request_timeout_seconds=max(5, _to_int(os.getenv("REQUEST_TIMEOUT_SECONDS"), 30)),
            bootstrap_notify_existing=_to_bool(os.getenv("BOOTSTRAP_NOTIFY_EXISTING"), False),
            data_dir=data_dir,
            reports_dir=reports_dir,
            database_path=database_path,
            telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN"),
            telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID"),
            github_token=os.getenv("GITHUB_TOKEN"),
            github_oauth_client_id=os.getenv("GITHUB_OAUTH_CLIENT_ID"),
            github_oauth_client_secret=os.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
            github_oauth_redirect_uri=os.getenv("GITHUB_OAUTH_REDIRECT_URI"),
            github_oauth_scope=os.getenv("GITHUB_OAUTH_SCOPE", "read:user user:email").strip(),
            bootstrap_admin_username=os.getenv("BOOTSTRAP_ADMIN_USERNAME", "owner").strip() or "owner",
            bootstrap_admin_api_key=(os.getenv("BOOTSTRAP_ADMIN_API_KEY") or "").strip() or None,
        )

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)

    @property
    def tracked_platform_set(self) -> set[str]:
        return {value.casefold() for value in self.track_platforms}
