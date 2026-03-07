from __future__ import annotations

import csv
import logging
import secrets
import shutil
import re
import threading
import math
import hashlib
import difflib
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .bbradar_client import BBRadarClient, BBRadarClientError
from .config import Settings
from .database import Database
from .github_client import GitHubClient, GitHubClientError
from .telegram_notifier import TelegramNotifier
from .vigilseek_client import VigilSeekClient, VigilSeekClientError
from .utils import (
    extract_pdf_summary,
    format_reward_range,
    parse_github_url,
    stable_program_hash,
    utc_now_iso,
)

logger = logging.getLogger(__name__)

REPORT_TEMPLATES: dict[str, dict[str, Any]] = {
    "hackenproof": {
        "platform": "HackenProof",
        "sections": [
            "Summary",
            "Impact",
            "Steps to Reproduce",
            "Proof of Concept",
            "Mitigation",
        ],
        "checklist": [
            "Include vulnerable contract/function names",
            "Attach transaction hash or logs",
            "Explain exploit preconditions",
            "State expected vs actual behavior",
        ],
    },
    "immunefi": {
        "platform": "Immunefi",
        "sections": [
            "Issue Summary",
            "Root Cause",
            "Impact",
            "Proof of Concept",
            "References",
        ],
        "checklist": [
            "Map finding to Immunefi severity criteria",
            "Provide clear attacker path",
            "Show funds/risk quantification",
            "List tested chain/network",
        ],
    },
    "sherlock": {
        "platform": "Sherlock",
        "sections": [
            "Title",
            "Description",
            "Impact",
            "Proof of Concept",
            "Recommendation",
        ],
        "checklist": [
            "PoC should compile/run",
            "Link to affected file/line",
            "Show why issue is valid under scope",
            "Mention assumptions explicitly",
        ],
    },
    "code4rena": {
        "platform": "Code4rena",
        "sections": [
            "Summary",
            "Vulnerability Details",
            "Impact",
            "Proof of Concept",
            "Tools Used",
            "Recommendations",
        ],
        "checklist": [
            "One issue per report",
            "Provide concrete exploit scenario",
            "Include impact justification",
            "Prefer deterministic PoC",
        ],
    },
}

WORKFLOW_TRANSITIONS: dict[str, set[str]] = {
    "submitted": {"triaged", "rejected"},
    "triaged": {"in_review", "rejected", "accepted"},
    "in_review": {"accepted", "rejected", "needs_info"},
    "needs_info": {"in_review", "rejected"},
    "accepted": {"resolved"},
    "rejected": set(),
    "resolved": set(),
}

INTELLIGENCE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "duplicate": ("duplicate", "already reported", "known issue"),
    "out_of_scope": ("out of scope", "outside scope", "nonscope", "not in scope"),
    "invalid": ("invalid", "cannot reproduce", "not reproducible", "false positive"),
    "informational": ("informational", "low impact", "best practice"),
    "insufficient_impact": ("no impact", "limited impact", "non exploitable"),
    "missing_poc": ("no poc", "missing poc", "insufficient details"),
}

PRE_AUDIT_FINDING_STATUSES = (
    "new",
    "triage",
    "validated",
    "false_positive",
    "report_drafted",
    "submitted",
    "resolved",
)

NOTIFICATION_RETRY_EVENT_TYPES = ("program_updated", "github_updated")
NOTIFICATION_RETRY_CANDIDATE_LIMIT = 100
NOTIFICATION_RETRY_SEND_LIMIT = 25
NOTIFICATION_RETRY_MIN_AGE_SECONDS = 120
NOTIFICATION_CHANNEL_DEFAULT = "default"
NOTIFICATION_CHANNEL_GITHUB = "github"

SOLIDITY_HEURISTIC_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "tx_origin_auth",
        "title": "Authentication via tx.origin",
        "severity": "high",
        "category": "access_control",
        "pattern": r"\btx\.origin\b",
        "description": "Use of tx.origin can enable phishing-style authorization bypasses.",
        "recommendation": "Use msg.sender-based access checks with explicit roles/ownership.",
        "confidence": 0.92,
    },
    {
        "id": "delegatecall_usage",
        "title": "delegatecall usage",
        "severity": "high",
        "category": "upgradeability",
        "pattern": r"\bdelegatecall\s*\(",
        "description": "delegatecall can execute untrusted logic in caller context if not tightly controlled.",
        "recommendation": "Restrict delegatecall targets and validate implementation contracts.",
        "confidence": 0.84,
    },
    {
        "id": "unchecked_block",
        "title": "Unchecked arithmetic block",
        "severity": "medium",
        "category": "math",
        "pattern": r"\bunchecked\s*\{",
        "description": "Unchecked arithmetic can hide overflow/underflow logic errors.",
        "recommendation": "Document invariants and ensure bounds are validated before unchecked math.",
        "confidence": 0.7,
    },
    {
        "id": "timestamp_dependency",
        "title": "Block timestamp dependency",
        "severity": "medium",
        "category": "oracle_time",
        "pattern": r"\bblock\.timestamp\b",
        "description": "Timestamp-based critical logic can be miner-influenced within small ranges.",
        "recommendation": "Avoid strict timestamp assumptions for security-critical conditions.",
        "confidence": 0.62,
    },
    {
        "id": "assembly_usage",
        "title": "Inline assembly usage",
        "severity": "medium",
        "category": "low_level",
        "pattern": r"\bassembly\s*\{",
        "description": "Inline assembly increases audit complexity and risk of memory/storage mistakes.",
        "recommendation": "Review memory safety assumptions and bounds in assembly blocks.",
        "confidence": 0.58,
    },
    {
        "id": "low_level_call",
        "title": "Low-level external call",
        "severity": "medium",
        "category": "external_call",
        "pattern": r"\.call\s*\{",
        "description": "Low-level call patterns may introduce reentrancy and error-handling issues.",
        "recommendation": "Apply checks-effects-interactions and reentrancy protections where needed.",
        "confidence": 0.67,
    },
    {
        "id": "selfdestruct_usage",
        "title": "selfdestruct usage",
        "severity": "high",
        "category": "lifecycle",
        "pattern": r"\bselfdestruct\s*\(",
        "description": "selfdestruct can permanently alter protocol behavior and token/account assumptions.",
        "recommendation": "Require strict governance controls and clear deprecation lifecycle.",
        "confidence": 0.9,
    },
)


class TrackerService:
    def __init__(self, settings: Settings, db: Database) -> None:
        self.settings = settings
        self.db = db
        self.bbradar_client = BBRadarClient(
            base_url=settings.bbradar_base_url,
            timeout_seconds=settings.request_timeout_seconds,
        )
        self.vigilseek_client = (
            VigilSeekClient(
                base_url=settings.vigilseek_base_url,
                timeout_seconds=settings.request_timeout_seconds,
            )
            if settings.vigilseek_enabled
            else None
        )
        self.github_client = GitHubClient(
            token=settings.github_token,
            timeout_seconds=settings.request_timeout_seconds,
        )
        self.notifier = TelegramNotifier(
            bot_token=settings.telegram_bot_token,
            chat_id=settings.telegram_chat_id,
            timeout_seconds=settings.request_timeout_seconds,
        )
        self.github_notifier = TelegramNotifier(
            bot_token=settings.github_telegram_bot_token,
            chat_id=settings.github_telegram_chat_id,
            timeout_seconds=settings.request_timeout_seconds,
        )

        self._bbradar_lock = threading.Lock()
        self._github_lock = threading.Lock()
        self._notification_lock = threading.Lock()
        self._job_lock = threading.Lock()
        self._status_lock = threading.Lock()
        self._shutdown_event = threading.Event()
        self._job_executor = ThreadPoolExecutor(
            max_workers=max(1, self.settings.job_worker_count),
            thread_name_prefix="scan-job",
        )
        self._job_futures: dict[int, Future[Any]] = {}
        self._status: dict[str, Any] = {
            "last_bbradar_run": None,
            "last_github_run": None,
            "last_notification_retry_run": None,
            "last_digest_run": None,
            "last_backup_run": None,
            "last_sla_run": None,
            "last_housekeeping_run": None,
            "startup_recovery": None,
        }
        self._bootstrap_admin_user()

    def _shutdown_requested(self) -> bool:
        return self._shutdown_event.is_set()

    def close(self) -> None:
        self._shutdown_event.set()
        self._job_executor.shutdown(wait=False, cancel_futures=False)
        self.bbradar_client.close()
        if self.vigilseek_client is not None:
            self.vigilseek_client.close()
        self.github_client.close()
        self.notifier.close()
        self.github_notifier.close()

    def health(self) -> dict[str, Any]:
        with self._status_lock:
            status_snapshot = dict(self._status)

        status_snapshot.update(
            {
                "telegram_enabled": self.notifier.enabled,
                "github_telegram_enabled": self.github_notifier.enabled,
                "github_token_configured": bool(self.settings.github_token),
                "github_oauth_configured": bool(
                    self.settings.github_oauth_client_id
                    and self.settings.github_oauth_client_secret
                    and self.settings.github_oauth_redirect_uri
                ),
                "tracked_platforms": self.settings.track_platforms,
                "tracked_scope_keywords": self.settings.track_scope_keywords,
                "vigilseek_enabled": self.settings.vigilseek_enabled,
                "scheduler": {
                    "bbradar_interval_minutes": self.settings.bbradar_interval_minutes,
                    "github_interval_minutes": self.settings.github_interval_minutes,
                    "notification_retry_interval_minutes": self.settings.notification_retry_interval_minutes,
                    "digest_enabled": self.settings.digest_enabled,
                    "digest_interval_hours": self.settings.digest_interval_hours,
                    "backup_enabled": self.settings.backup_enabled,
                    "backup_interval_hours": self.settings.backup_interval_hours,
                    "sla_reminder_enabled": self.settings.sla_reminder_enabled,
                    "sla_reminder_interval_minutes": self.settings.sla_reminder_interval_minutes,
                    "housekeeping_enabled": self.settings.housekeeping_enabled,
                    "housekeeping_interval_hours": self.settings.housekeeping_interval_hours,
                },
                "queue": self.get_queue_overview(),
            }
        )
        return status_snapshot

    def _set_last_status(self, key: str, status: dict[str, Any]) -> None:
        with self._status_lock:
            self._status[key] = status

    @staticmethod
    def _mask_secrets(text: str) -> str:
        masked = str(text or "")
        masked = re.sub(r"github_pat_[A-Za-z0-9_]+", "github_pat_***", masked)
        masked = re.sub(r"\bgh[pousr]_[A-Za-z0-9]+\b", "gh***", masked)
        masked = re.sub(r"\b\d{6,12}:[A-Za-z0-9_-]{20,}\b", "***:***", masked)
        return masked

    def _hash_api_key(self, api_key: str) -> str:
        payload = f"{self.settings.api_key_signing_secret}:{api_key}".encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def _api_key_matches(self, stored: str, candidate: str) -> bool:
        stored_text = str(stored or "")
        if stored_text.startswith("sha256:"):
            return stored_text == self._hash_api_key(candidate)
        return stored_text == candidate

    def _job_target(self, job_type: str):
        mapping = {
            "scan_bbradar": self.scan_bbradar,
            "scan_github": self.scan_github,
            "digest": self.run_daily_digest,
            "backup": self.run_backup_export,
            "sla_reminder": self.run_sla_reminders,
            "housekeeping": self.run_housekeeping,
        }
        return mapping.get(job_type)

    def enqueue_scan_job(
        self,
        *,
        job_type: str,
        trigger: str = "manual",
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        target = self._job_target(job_type)
        if target is None:
            raise ValueError(f"unsupported job type: {job_type}")
        now_iso = utc_now_iso()
        job = self.db.create_scan_job(
            job_type=job_type,
            trigger=trigger,
            payload=payload or {},
            now_iso=now_iso,
        )
        job_id = int(job["id"])
        try:
            future = self._job_executor.submit(
                self._run_scan_job_worker,
                job_id=job_id,
                job_type=job_type,
                trigger=trigger,
            )
        except RuntimeError as exc:
            logger.exception("job queue unavailable, failed to enqueue %s: %s", job_type, exc)
            self.db.update_scan_job(
                job_id,
                status="error",
                finished_at=utc_now_iso(),
                error="job queue unavailable",
            )
            failed = self.db.get_scan_job(job_id)
            return failed or job

        with self._job_lock:
            self._job_futures[job_id] = future
        return job

    def _run_scan_job_worker(self, *, job_id: int, job_type: str, trigger: str) -> None:
        started_at = utc_now_iso()
        self.db.update_scan_job(job_id, status="running", started_at=started_at, error=None)
        target = self._job_target(job_type)
        if target is None:
            self.db.update_scan_job(
                job_id,
                status="error",
                finished_at=utc_now_iso(),
                error=f"unsupported job type: {job_type}",
            )
            return
        try:
            result = target(trigger=f"job:{trigger}")
            self.db.update_scan_job(
                job_id,
                status="done",
                finished_at=utc_now_iso(),
                result=result,
                error=None,
            )
        except Exception as exc:
            logger.exception("scan job %s failed: %s", job_id, exc)
            self.db.update_scan_job(
                job_id,
                status="error",
                finished_at=utc_now_iso(),
                error=self._mask_secrets(str(exc)),
            )
        finally:
            with self._job_lock:
                self._job_futures.pop(job_id, None)

    def get_scan_job(self, job_id: int) -> dict[str, Any] | None:
        return self.db.get_scan_job(job_id)

    def list_scan_jobs(self, limit: int = 100, status: str | None = None) -> list[dict[str, Any]]:
        return self.db.list_scan_jobs(limit=limit, status=status)

    def get_queue_overview(self) -> dict[str, Any]:
        jobs = self.db.list_scan_jobs(limit=400)
        counter: Counter[str] = Counter(str(job.get("status") or "unknown") for job in jobs)
        with self._job_lock:
            active_futures = sum(1 for future in self._job_futures.values() if not future.done())
            tracked_futures = len(self._job_futures)
        return {
            "queued": counter.get("queued", 0),
            "running": counter.get("running", 0),
            "done": counter.get("done", 0),
            "error": counter.get("error", 0),
            "recent_total": len(jobs),
            "worker_count": max(1, self.settings.job_worker_count),
            "active_workers": active_futures,
            "tracked_futures": tracked_futures,
        }

    def recover_after_restart(self) -> dict[str, Any]:
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        # Any queued/running job from a previous process should be marked stale.
        # It cannot resume safely after process restart because in-memory workers are gone.
        stale_before_iso = (now_dt + timedelta(seconds=1)).isoformat()
        stale_jobs = self.db.mark_stale_scan_jobs(stale_before_iso=stale_before_iso, now_iso=now_iso)
        result = {
            "status": "ok",
            "completed_at": now_iso,
            "stale_before": stale_before_iso,
            "stale_jobs_marked": stale_jobs,
        }
        self._set_last_status("startup_recovery", result)
        if stale_jobs > 0:
            self.db.insert_event(
                event_type="maintenance_recovery",
                title=f"Recovered {stale_jobs} stale job(s) after restart",
                details=result,
                created_at=now_iso,
                notified=False,
            )
        return result

    def run_housekeeping(self, trigger: str = "scheduler") -> dict[str, Any]:
        started_dt = datetime.now(timezone.utc)
        started_at = started_dt.isoformat()
        stale_before_iso = (started_dt - timedelta(minutes=max(5, self.settings.stale_job_timeout_minutes))).isoformat()
        event_cutoff_iso = (started_dt - timedelta(days=max(7, self.settings.event_retention_days))).isoformat()
        job_cutoff_iso = (started_dt - timedelta(days=max(3, self.settings.job_retention_days))).isoformat()

        try:
            stale_jobs = self.db.mark_stale_scan_jobs(stale_before_iso=stale_before_iso, now_iso=started_at)
            deleted_events = self.db.prune_events(older_than_iso=event_cutoff_iso)
            deleted_jobs = self.db.prune_scan_jobs(older_than_iso=job_cutoff_iso)
            summary = {
                "status": "ok",
                "trigger": trigger,
                "started_at": started_at,
                "stale_jobs_marked": stale_jobs,
                "deleted_events": deleted_events,
                "deleted_jobs": deleted_jobs,
                "event_retention_days": self.settings.event_retention_days,
                "job_retention_days": self.settings.job_retention_days,
            }
            self._set_last_status("last_housekeeping_run", summary)
            if stale_jobs or deleted_events or deleted_jobs:
                self.db.insert_event(
                    event_type="maintenance_housekeeping",
                    title="Housekeeping completed",
                    details=summary,
                    created_at=started_at,
                    notified=False,
                )
            return summary
        except Exception as exc:
            logger.exception("housekeeping failed: %s", exc)
            summary = {
                "status": "error",
                "trigger": trigger,
                "started_at": started_at,
                "error": self._mask_secrets(str(exc)),
            }
            self._set_last_status("last_housekeeping_run", summary)
            self.db.insert_event(
                event_type="run_error",
                title="housekeeping failed",
                details=summary,
                created_at=started_at,
                notified=False,
            )
            return summary

    def _bootstrap_admin_user(self) -> None:
        if not self.settings.bootstrap_admin_api_key:
            return
        for user in self.db.list_users(active_only=False):
            if self._api_key_matches(str(user.get("api_key") or ""), self.settings.bootstrap_admin_api_key):
                return
        now_iso = utc_now_iso()
        try:
            self.db.create_user(
                {
                    "username": self.settings.bootstrap_admin_username,
                    "role": "admin",
                    "api_key": self._hash_api_key(self.settings.bootstrap_admin_api_key),
                    "active": True,
                },
                now_iso=now_iso,
            )
        except Exception:
            logger.exception("failed to bootstrap admin user")

    @staticmethod
    def _parse_utc_iso(value: str | None) -> datetime | None:
        if not value:
            return None
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @staticmethod
    def _is_not_found_watch_error(error: str | None) -> bool:
        if not error:
            return False
        text = error.casefold()
        return "github request failed (404): not found" in text

    @staticmethod
    def _is_rate_limit_error(exc: GitHubClientError) -> bool:
        if exc.status_code not in {403, 429}:
            return False
        return "rate limit" in str(exc).casefold()

    def _matches_filters(self, item: dict[str, Any]) -> bool:
        platform = str(item.get("platform") or "").casefold()
        if self.settings.tracked_platform_set and platform not in self.settings.tracked_platform_set:
            return False

        if self.settings.track_scope_keywords:
            scope_tags = item.get("scope_tags") or []
            scope_blob = " ".join([str(item.get("scope_type") or "")] + [str(tag) for tag in scope_tags])
            lowered_scope_blob = scope_blob.casefold()
            if not any(keyword in lowered_scope_blob for keyword in self.settings.track_scope_keywords):
                return False

        return True

    @staticmethod
    def _as_float(value: Any) -> float | None:
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _slugify(value: str) -> str:
        text = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
        return text or "unknown-handle"

    @staticmethod
    def _normalize_link(link: str | None) -> str:
        text = str(link or "").strip()
        if not text:
            return ""
        try:
            split = urlsplit(text)
        except ValueError:
            return text.casefold().rstrip("/")
        scheme = (split.scheme or "https").casefold()
        host = split.netloc.casefold()
        path = split.path.rstrip("/")
        if not host:
            return text.casefold().rstrip("/")
        return f"{scheme}://{host}{path}"

    @staticmethod
    def _program_identity_key(platform: str, name: str) -> tuple[str, str]:
        return (platform.casefold().strip(), name.casefold().strip())

    def _normalize_program(self, item: dict[str, Any], source: str = "bbradar") -> dict[str, Any]:
        if source == "bbradar":
            platform = str(item.get("platform") or "Unknown").strip()
            handle = str(item.get("handle") or "unknown-handle").strip()
            scope_tags = item.get("scope_tags") or []
            if not isinstance(scope_tags, list):
                scope_tags = []

            payload = {
                "source": "bbradar",
                "external_id": f"{platform}:{handle}",
                "platform": platform,
                "handle": handle,
                "name": str(item.get("name") or "Unnamed Program").strip(),
                "link": str(item.get("link") or "").strip(),
                "date_launched": str(item.get("date_launched") or "").strip(),
                "scope_type": str(item.get("scope_type") or "").strip(),
                "scope_tags": [str(tag) for tag in scope_tags],
                "bounty_min": self._as_float(item.get("bounty_min")),
                "bounty_max": self._as_float(item.get("bounty_max")),
            }
            payload["raw_json"] = dict(payload)
            payload["data_hash"] = stable_program_hash(payload)
            return payload

        if source == "vigilseek":
            platform = str(item.get("platform") or "Unknown").strip()
            link = str(item.get("originalUrl") or "").strip()
            slug = str(item.get("slug") or "").strip()
            if not slug and link:
                parsed = urlsplit(link)
                slug = parsed.path.rstrip("/").split("/")[-1]
            if not slug:
                slug = self._slugify(str(item.get("project") or ""))

            tags = item.get("tags") or []
            if not isinstance(tags, list):
                tags = []
            languages = item.get("languages") or []
            if not isinstance(languages, list):
                languages = []

            clean_tags = [str(tag).strip().lstrip("#") for tag in tags if str(tag).strip()]
            clean_languages = [str(lang).strip() for lang in languages if str(lang).strip()]

            scope_tags = clean_tags + clean_languages
            scope_type = ", ".join(clean_tags[:2])

            payload = {
                "source": "vigilseek",
                "external_id": f"{platform}:{slug}",
                "platform": platform,
                "handle": slug,
                "name": str(item.get("project") or "Unnamed Program").strip(),
                "link": link,
                "date_launched": str(item.get("startDate") or "").strip(),
                "scope_type": scope_type,
                "scope_tags": scope_tags,
                "bounty_min": None,
                "bounty_max": self._as_float(item.get("maxReward")),
            }
            raw_payload = dict(payload)
            raw_payload["vigilseek_id"] = str(item.get("id") or "")
            raw_payload["languages"] = clean_languages
            raw_payload["tags"] = clean_tags
            payload["raw_json"] = raw_payload
            payload["data_hash"] = stable_program_hash(payload)
            return payload

        raise ValueError(f"unsupported source: {source}")

    def _is_duplicate_program(
        self,
        *,
        normalized: dict[str, Any],
        external_ids: set[str],
        links: set[str],
        platform_name_keys: set[tuple[str, str]],
    ) -> bool:
        external_id = str(normalized.get("external_id") or "").casefold()
        link = self._normalize_link(normalized.get("link"))
        platform = str(normalized.get("platform") or "")
        name = str(normalized.get("name") or "")
        key = self._program_identity_key(platform, name)

        if external_id and external_id in external_ids:
            return True
        if link and link in links:
            return True
        if key in platform_name_keys:
            return True
        return False

    def _recent_github_activity_counter(self, days: int = 7) -> Counter[str]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))
        counter: Counter[str] = Counter()
        for event in self.db.list_events(limit=5000, event_type="github_updated"):
            created = self._parse_utc_iso(str(event.get("created_at") or ""))
            if not created or created < cutoff:
                continue
            external_id = str(event.get("program_external_id") or "").strip()
            if external_id:
                counter[external_id] += 1
        return counter

    def _compute_priority_score(
        self,
        program: dict[str, Any],
        *,
        watch_count: int = 0,
        recent_github_updates: int = 0,
    ) -> float:
        bounty_ref = self._as_float(program.get("bounty_max"))
        if bounty_ref is None:
            bounty_ref = self._as_float(program.get("bounty_min")) or 0.0
        bounty_ref = max(0.0, min(1_000_000.0, bounty_ref))
        bounty_score = min(45.0, (math.log10(bounty_ref + 1.0) / 6.0) * 45.0)

        changed = self._parse_utc_iso(str(program.get("last_changed_at") or ""))
        recency_score = 0.0
        if changed:
            age_days = max(0.0, (datetime.now(timezone.utc) - changed).total_seconds() / 86400.0)
            recency_score = max(0.0, 25.0 - (age_days * 1.5))

        watch_score = min(15.0, max(0, watch_count) * 3.0)
        activity_score = min(12.0, max(0, recent_github_updates) * 2.5)
        platform_bonus_map = {
            "hackenproof": 3.0,
            "immunefi": 2.5,
            "sherlock": 2.0,
            "code4rena": 2.0,
        }
        platform_bonus = platform_bonus_map.get(str(program.get("platform") or "").casefold(), 1.0)

        total = min(100.0, bounty_score + recency_score + watch_score + activity_score + platform_bonus)
        return round(total, 2)

    @staticmethod
    def _parse_scope_sections(program: dict[str, Any]) -> dict[str, list[str]]:
        raw = program.get("raw") or {}
        scope_tags = raw.get("scope_tags") if isinstance(raw, dict) else []
        if not isinstance(scope_tags, list):
            scope_tags = []
        includes: list[str] = []
        excludes: list[str] = []
        for tag in scope_tags:
            text = str(tag).strip()
            lowered = text.casefold()
            if any(token in lowered for token in ("out", "exclude", "excluded", "not in scope", "offscope")):
                excludes.append(text)
            else:
                includes.append(text)
        return {
            "includes": includes[:50],
            "excludes": excludes[:50],
        }

    def list_programs_with_priority(
        self,
        *,
        limit: int = 100,
        platform: str | None = None,
        updated_only: bool = False,
        focus: str = "all",
        q: str | None = None,
    ) -> list[dict[str, Any]]:
        programs = self.db.list_programs(
            limit=max(1, limit),
            platform=platform,
            updated_only=updated_only,
            focus=focus,
            q=q,
        )
        watches = self.db.list_github_watches(active_only=True)
        watch_counter: Counter[str] = Counter()
        for watch in watches:
            external_id = str(watch.get("program_external_id") or "").strip()
            if external_id:
                watch_counter[external_id] += 1
        recent_counter = self._recent_github_activity_counter(days=7)
        boost_counter: Counter[str] = Counter()
        tags_by_program: dict[str, list[dict[str, Any]]] = {}
        for tag_row in self.db.list_program_tags():
            external_id = str(tag_row.get("program_external_id") or "").strip()
            if not external_id:
                continue
            boost = float(tag_row.get("manual_boost") or 0.0)
            if boost:
                boost_counter[external_id] += boost
            tags_by_program.setdefault(external_id, []).append(tag_row)
        for program in programs:
            external_id = str(program.get("external_id") or "")
            program["priority_score"] = self._compute_priority_score(
                program,
                watch_count=watch_counter.get(external_id, 0),
                recent_github_updates=recent_counter.get(external_id, 0),
            )
            if boost_counter.get(external_id):
                program["priority_score"] = round(
                    min(100.0, float(program["priority_score"]) + float(boost_counter[external_id])),
                    2,
                )
            program["tags"] = tags_by_program.get(external_id, [])
        programs.sort(key=lambda p: float(p.get("priority_score") or 0.0), reverse=True)
        return programs[: max(1, limit)]

    def get_program_detail(self, external_id: str, event_limit: int = 30) -> dict[str, Any] | None:
        program = self.db.get_program(external_id)
        if program is None:
            return None
        watches = self.db.list_program_watches(external_id=external_id, active_only=False)
        events = self.db.list_program_events(external_id=external_id, limit=max(1, event_limit))
        timeline = self.get_program_timeline(external_id=external_id, limit=max(1, event_limit))
        submissions = self.db.list_program_submissions(program_name=str(program.get("name") or ""), limit=50)
        recent_counter = self._recent_github_activity_counter(days=7)
        tags = self.db.list_program_tags(program_external_id=external_id)

        scope = self._parse_scope_sections(program)
        detail = {
            "program": {
                **program,
                "priority_score": self._compute_priority_score(
                    program,
                    watch_count=len([w for w in watches if int(w.get("active") or 0) == 1]),
                    recent_github_updates=recent_counter.get(external_id, 0),
                ),
                "scope_includes": scope["includes"],
                "scope_excludes": scope["excludes"],
                "tags": tags,
            },
            "watches": watches,
            "events": events,
            "timeline": timeline,
            "submissions": submissions,
            "summary": {
                "active_watches": len([w for w in watches if int(w.get("active") or 0) == 1]),
                "event_count": len(events),
                "timeline_count": len(timeline),
                "submission_count": len(submissions),
                "recent_github_updates_7d": recent_counter.get(external_id, 0),
            },
        }
        return detail

    def list_submissions_kanban(self, limit_per_status: int = 100) -> dict[str, Any]:
        statuses = ["idea", "draft", "submitted", "triaged", "accepted", "rejected", "resolved"]
        all_items = self.db.list_submissions(limit=5000)
        columns: dict[str, list[dict[str, Any]]] = {status: [] for status in statuses}
        columns["other"] = []
        for item in all_items:
            status = str(item.get("status") or "").casefold()
            key = status if status in columns else "other"
            if len(columns[key]) < max(1, limit_per_status):
                columns[key].append(item)
        return {
            "columns": columns,
            "counts": {key: len(value) for key, value in columns.items()},
            "total": sum(len(value) for value in columns.values()),
        }

    def get_rejection_analytics(self, top_n: int = 10) -> dict[str, Any]:
        submissions = self.db.list_submissions(limit=5000)
        rejected = [
            item
            for item in submissions
            if str(item.get("status") or "").casefold() == "rejected" or item.get("rejection_reason")
        ]

        reason_counter: Counter[str] = Counter()
        keyword_counter: Counter[str] = Counter()
        for item in rejected:
            reason = str(item.get("rejection_reason") or "unspecified").strip() or "unspecified"
            reason_counter[reason] += 1
            blob = " ".join(
                [
                    str(item.get("rejection_reason") or ""),
                    str(item.get("triage_notes") or ""),
                ]
            ).casefold()
            for word in re.findall(r"[a-z][a-z0-9_-]{3,}", blob):
                if word in {"with", "that", "have", "from", "this", "your", "they", "were"}:
                    continue
                keyword_counter[word] += 1

        return {
            "rejected_total": len(rejected),
            "top_reasons": [
                {"reason": reason, "count": count}
                for reason, count in reason_counter.most_common(max(1, top_n))
            ],
            "top_keywords": [
                {"keyword": keyword, "count": count}
                for keyword, count in keyword_counter.most_common(max(1, top_n))
            ],
        }

    def get_watch_health(self, lookback_hours: int = 24 * 7, stale_hours: int = 48) -> dict[str, Any]:
        watches = self.db.list_github_watches(active_only=False)
        now_dt = datetime.now(timezone.utc)
        stale_cutoff = now_dt - timedelta(hours=max(1, stale_hours))
        error_cutoff = now_dt - timedelta(hours=max(1, lookback_hours))

        stale_watches: list[dict[str, Any]] = []
        by_id = {int(w.get("id")): w for w in watches}
        for watch in watches:
            checked = self._parse_utc_iso(str(watch.get("last_checked_at") or ""))
            if int(watch.get("active") or 0) == 1 and (checked is None or checked < stale_cutoff):
                stale_watches.append(watch)

        error_counter: Counter[int] = Counter()
        latest_error: dict[int, str] = {}
        for event in self.db.list_events(limit=10000, event_type="run_error"):
            created = self._parse_utc_iso(str(event.get("created_at") or ""))
            if not created or created < error_cutoff:
                continue
            details = event.get("details") or {}
            watch_id = details.get("watch_id")
            if watch_id is None:
                continue
            try:
                watch_id_int = int(watch_id)
            except (TypeError, ValueError):
                continue
            error_counter[watch_id_int] += 1
            latest_error[watch_id_int] = str(details.get("error") or "")

        unhealthy: list[dict[str, Any]] = []
        for watch_id, count in error_counter.most_common(30):
            watch = by_id.get(watch_id)
            if not watch:
                continue
            unhealthy.append(
                {
                    "watch_id": watch_id,
                    "repo": f"{watch.get('repo_owner')}/{watch.get('repo_name')}",
                    "file_path": watch.get("file_path") or "",
                    "branch": watch.get("branch") or "main",
                    "active": int(watch.get("active") or 0),
                    "error_count": count,
                    "latest_error": latest_error.get(watch_id, ""),
                }
            )

        return {
            "total_watches": len(watches),
            "active_watches": len([w for w in watches if int(w.get("active") or 0) == 1]),
            "stale_active_watches": len(stale_watches),
            "stale_samples": stale_watches[:25],
            "unhealthy_samples": unhealthy,
            "lookback_hours": lookback_hours,
            "stale_hours": stale_hours,
        }

    def get_source_coverage(self) -> dict[str, Any]:
        programs = self.db.list_programs(limit=200000, focus="all")
        by_source: Counter[str] = Counter()
        by_platform: Counter[str] = Counter()
        source_platform: Counter[tuple[str, str]] = Counter()
        for program in programs:
            source = str(program.get("source") or "unknown")
            platform = str(program.get("platform") or "unknown")
            by_source[source] += 1
            by_platform[platform] += 1
            source_platform[(source, platform)] += 1

        source_platform_rows = [
            {"source": source, "platform": platform, "count": count}
            for (source, platform), count in sorted(source_platform.items(), key=lambda item: (-item[1], item[0][0]))
        ]
        return {
            "total_programs": len(programs),
            "by_source": dict(by_source),
            "by_platform": dict(by_platform),
            "source_platform": source_platform_rows[:200],
        }

    def create_alert_rule(self, payload: dict[str, Any]) -> dict[str, Any]:
        now_iso = utc_now_iso()
        return self.db.create_alert_rule(payload, now_iso=now_iso)

    def list_alert_rules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        return self.db.list_alert_rules(enabled_only=enabled_only)

    def update_alert_rule(self, rule_id: int, updates: dict[str, Any]) -> dict[str, Any] | None:
        return self.db.update_alert_rule(rule_id, updates=updates, now_iso=utc_now_iso())

    def delete_alert_rule(self, rule_id: int) -> bool:
        return self.db.delete_alert_rule(rule_id)

    def _rule_matches(self, rule: dict[str, Any], *, event_type: str, context: dict[str, Any]) -> bool:
        enabled = bool(int(rule.get("enabled") or 0))
        if not enabled:
            return False

        event_types = [str(value).strip() for value in (rule.get("event_types") or []) if str(value).strip()]
        if event_types and event_type not in event_types:
            return False

        platforms = [str(value).casefold().strip() for value in (rule.get("platforms") or []) if str(value).strip()]
        platform = str(context.get("platform") or "").casefold().strip()
        if platforms and platform not in platforms:
            return False

        min_bounty = self._as_float(rule.get("min_bounty"))
        bounty_max = self._as_float(context.get("bounty_max"))
        if min_bounty is not None and (bounty_max is None or bounty_max < min_bounty):
            return False

        keywords = [str(value).casefold().strip() for value in (rule.get("keywords") or []) if str(value).strip()]
        if keywords:
            text = str(context.get("text") or "").casefold()
            if not any(keyword in text for keyword in keywords):
                return False

        return True

    def _should_send_immediate_alert(self, *, event_type: str, context: dict[str, Any]) -> bool:
        rules = self.db.list_alert_rules(enabled_only=True)
        if not rules:
            return True
        for rule in rules:
            if int(rule.get("digest_only") or 0) == 1:
                continue
            if self._rule_matches(rule, event_type=event_type, context=context):
                return True
        return False

    def create_team_user(self, *, username: str, role: str, active: bool = True) -> dict[str, Any]:
        plain_api_key = secrets.token_urlsafe(32)
        payload = {
            "username": username.strip(),
            "role": role.strip().casefold(),
            "api_key": self._hash_api_key(plain_api_key),
            "active": bool(active),
        }
        created = self.db.create_user(payload, now_iso=utc_now_iso())
        created["api_key"] = plain_api_key
        return created

    def list_team_users(self, active_only: bool = False) -> list[dict[str, Any]]:
        return self.db.list_users(active_only=active_only)

    def update_team_user(self, user_id: int, updates: dict[str, Any]) -> dict[str, Any] | None:
        clean = dict(updates)
        if "role" in clean and clean["role"] is not None:
            clean["role"] = str(clean["role"]).casefold().strip()
        return self.db.update_user(user_id=user_id, updates=clean, now_iso=utc_now_iso())

    def rotate_team_user_api_key(self, user_id: int) -> dict[str, Any] | None:
        plain_api_key = secrets.token_urlsafe(32)
        updated = self.db.update_user(
            user_id=user_id,
            updates={"api_key": self._hash_api_key(plain_api_key)},
            now_iso=utc_now_iso(),
        )
        if updated is None:
            return None
        updated["api_key"] = plain_api_key
        return updated

    def delete_team_user(self, user_id: int) -> bool:
        return self.db.delete_user(user_id)

    def authenticate_api_key(self, api_key: str | None) -> dict[str, Any] | None:
        if not api_key:
            return None
        for user in self.db.list_users(active_only=True):
            stored = str(user.get("api_key") or "")
            if self._api_key_matches(stored, api_key):
                return user
        return None

    def run_daily_digest(self, trigger: str = "scheduler") -> dict[str, Any]:
        started_at = utc_now_iso()
        last_state = self.db.get_state("daily_digest")
        since_iso = str((last_state or {}).get("last_sent_at") or "")
        since_dt = self._parse_utc_iso(since_iso)
        if since_dt is None:
            since_dt = datetime.now(timezone.utc) - timedelta(hours=max(1, self.settings.digest_interval_hours))

        events = self.db.list_events(limit=5000)
        selected: list[dict[str, Any]] = []
        for event in events:
            created = self._parse_utc_iso(str(event.get("created_at") or ""))
            if not created or created <= since_dt:
                continue
            selected.append(event)
        selected.sort(key=lambda item: str(item.get("created_at") or ""))

        if not selected:
            summary = {
                "status": "ok",
                "trigger": trigger,
                "started_at": started_at,
                "events_in_digest": 0,
                "sent": False,
            }
            self._set_last_status("last_digest_run", summary)
            return summary

        type_counter = Counter(str(item.get("event_type") or "unknown") for item in selected)
        lines = [
            "[DAILY DIGEST]",
            f"Since: {since_dt.isoformat()}",
            f"Total events: {len(selected)}",
        ]
        for event_type, count in type_counter.most_common():
            lines.append(f"- {event_type}: {count}")
        lines.append("")
        for event in selected[:12]:
            lines.append(f"* {event.get('title')}")
        if len(selected) > 12:
            lines.append(f"... and {len(selected) - 12} more")

        sent = self._safe_send_notification("\n".join(lines))
        if sent:
            self.db.set_state(
                "daily_digest",
                {"last_sent_at": started_at, "last_count": len(selected)},
                now_iso=started_at,
            )

        summary = {
            "status": "ok",
            "trigger": trigger,
            "started_at": started_at,
            "events_in_digest": len(selected),
            "sent": sent,
        }
        self._set_last_status("last_digest_run", summary)
        return summary

    def run_backup_export(self, trigger: str = "scheduler") -> dict[str, Any]:
        started_at = utc_now_iso()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_dir = self.settings.data_dir / "backups"
        export_dir = self.settings.data_dir / "exports"
        backup_dir.mkdir(parents=True, exist_ok=True)
        export_dir.mkdir(parents=True, exist_ok=True)

        db_backup_path = backup_dir / f"tracker_{timestamp}.db"
        programs_csv_path = export_dir / f"programs_{timestamp}.csv"
        submissions_csv_path = export_dir / f"submissions_{timestamp}.csv"

        shutil.copy2(self.settings.database_path, db_backup_path)

        programs = self.db.list_programs(limit=200000, focus="all")
        submissions = self.db.list_submissions(limit=100000)

        with programs_csv_path.open("w", encoding="utf-8", newline="") as fp:
            writer = csv.writer(fp)
            writer.writerow(
                [
                    "source",
                    "external_id",
                    "platform",
                    "name",
                    "link",
                    "date_launched",
                    "scope_type",
                    "bounty_min",
                    "bounty_max",
                    "first_seen_at",
                    "last_changed_at",
                ]
            )
            for item in programs:
                writer.writerow(
                    [
                        item.get("source"),
                        item.get("external_id"),
                        item.get("platform"),
                        item.get("name"),
                        item.get("link"),
                        item.get("date_launched"),
                        item.get("scope_type"),
                        item.get("bounty_min"),
                        item.get("bounty_max"),
                        item.get("first_seen_at"),
                        item.get("last_changed_at"),
                    ]
                )

        with submissions_csv_path.open("w", encoding="utf-8", newline="") as fp:
            writer = csv.writer(fp)
            writer.writerow(
                [
                    "id",
                    "platform",
                    "program_name",
                    "bug_title",
                    "severity",
                    "status",
                    "submitted_at",
                    "rejection_reason",
                    "updated_at",
                ]
            )
            for item in submissions:
                writer.writerow(
                    [
                        item.get("id"),
                        item.get("platform"),
                        item.get("program_name"),
                        item.get("bug_title"),
                        item.get("severity"),
                        item.get("status"),
                        item.get("submitted_at"),
                        item.get("rejection_reason"),
                        item.get("updated_at"),
                    ]
                )

        result = {
            "status": "ok",
            "trigger": trigger,
            "started_at": started_at,
            "backup_db": str(db_backup_path),
            "programs_csv": str(programs_csv_path),
            "submissions_csv": str(submissions_csv_path),
            "program_rows": len(programs),
            "submission_rows": len(submissions),
        }
        self._set_last_status("last_backup_run", result)
        return result

    def _notifier_for_channel(self, channel: str) -> TelegramNotifier:
        if channel == NOTIFICATION_CHANNEL_GITHUB and self.github_notifier.enabled:
            return self.github_notifier
        return self.notifier

    def _safe_send_notification(self, text: str, *, channel: str = NOTIFICATION_CHANNEL_DEFAULT) -> bool:
        safe_text = self._mask_secrets(text)
        notifier = self._notifier_for_channel(channel)
        try:
            return notifier.send_message(safe_text)
        except Exception as exc:  # pragma: no cover - network behavior
            logger.exception("telegram notification failed: %s", exc)
            self.db.insert_event(
                event_type="notification_error",
                title="Telegram notification failed",
                details={
                    "channel": channel,
                    "error": self._mask_secrets(str(exc)),
                    "sample": safe_text[:500],
                },
                created_at=utc_now_iso(),
            )
            return False

    def _maybe_send_source_health_alert(self, *, source: str, error: str) -> None:
        key = f"source_health_alert:{source.casefold()}"
        now_iso = utc_now_iso()
        now_dt = self._parse_utc_iso(now_iso) or datetime.now(timezone.utc)
        previous = self.db.get_state(key) or {}
        last_sent = self._parse_utc_iso(str(previous.get("last_sent_at") or ""))
        cooldown = timedelta(minutes=max(5, self.settings.source_alert_cooldown_minutes))
        if last_sent and now_dt - last_sent < cooldown:
            return

        text = "\n".join(
            [
                "[SOURCE HEALTH ALERT]",
                f"Source: {source}",
                f"When: {now_iso}",
                f"Error: {self._mask_secrets(error)[:800]}",
            ]
        )
        sent = self._safe_send_notification(text)
        self.db.set_state(
            key,
            {
                "last_sent_at": now_iso if sent else str(previous.get("last_sent_at") or ""),
                "last_error": self._mask_secrets(error)[:800],
            },
            now_iso=now_iso,
        )

    @staticmethod
    def _display_changed_fields(changed_fields: list[str]) -> str:
        if not changed_fields:
            return "details_changed"
        return ", ".join(changed_fields)

    @staticmethod
    def _parse_program_from_event_title(title: str | None) -> tuple[str | None, str | None]:
        text = str(title or "").strip()
        match = re.match(r"^Program updated: (?P<name>.+) \((?P<platform>.+)\)$", text)
        if not match:
            return None, None
        return match.group("name").strip() or None, match.group("platform").strip() or None

    def _build_new_program_message(self, item: dict[str, Any]) -> str:
        return "\n".join(
            [
                "[NEW PROGRAM]",
                f"Platform: {item['platform']}",
                f"Name: {item['name']}",
                f"Launched: {item.get('date_launched') or 'unknown'}",
                f"Scope: {item.get('scope_type') or 'unknown'}",
                f"Reward: {format_reward_range(item.get('bounty_min'), item.get('bounty_max'))}",
                f"Link: {item.get('link') or 'n/a'}",
                f"Program ID: {item['external_id']}",
            ]
        )

    def _build_program_updated_message(self, item: dict[str, Any], changed_fields: list[str]) -> str:
        return "\n".join(
            [
                "[PROGRAM UPDATED]",
                f"Platform: {item['platform']}",
                f"Name: {item['name']}",
                f"Changed: {self._display_changed_fields(changed_fields)}",
                f"Reward: {format_reward_range(item.get('bounty_min'), item.get('bounty_max'))}",
                f"Link: {item.get('link') or 'n/a'}",
                f"Program ID: {item['external_id']}",
            ]
        )

    def _is_noisy_immunefi_bounty_min_update(
        self,
        *,
        platform: str | None,
        changed_fields: list[str],
        field_diffs: dict[str, dict[str, Any]],
    ) -> bool:
        if str(platform or "").casefold().strip() != "immunefi":
            return False

        unique_fields = {str(field).strip() for field in changed_fields if str(field).strip()}
        if unique_fields != {"bounty_min"}:
            return False

        diff = field_diffs.get("bounty_min")
        if not isinstance(diff, dict):
            return False

        old_value = self._as_float(diff.get("old"))
        new_value = self._as_float(diff.get("new"))
        if old_value is None or new_value is None:
            return False

        # bbradar sometimes flips Immunefi minimum bounty between 0 and non-zero across runs.
        # Suppress immediate Telegram alerts for this noisy pattern.
        old_is_zero = abs(old_value) < 1e-9
        new_is_zero = abs(new_value) < 1e-9
        return old_is_zero != new_is_zero

    def _build_github_update_message(
        self,
        *,
        watch: dict[str, Any],
        old_sha: str,
        new_sha: str,
        html_url: str,
        program_name: str | None,
        changed_files: list[dict[str, str]] | None = None,
        observed_branch: str | None = None,
    ) -> str:
        path = watch["file_path"] or "<repo branch>"
        lines = [
            "[GITHUB UPDATED]",
            f"Repo: {watch['repo_owner']}/{watch['repo_name']}",
            f"Path: {path}",
            f"Branch: {observed_branch or watch['branch']}",
            f"Old SHA: {old_sha[:12]}",
            f"New SHA: {new_sha[:12]}",
            f"Link: {html_url}",
        ]
        files = changed_files or []
        if files:
            display = ", ".join(item.get("filename", "") for item in files[:5] if item.get("filename"))
            if display:
                suffix = "..." if len(files) > 5 else ""
                lines.append(f"Files: {display}{suffix}")
        if program_name:
            lines.append(f"Program: {program_name}")
        return "\n".join(lines)

    def _notification_payload_from_event(self, event: dict[str, Any]) -> tuple[str, str, dict[str, Any]] | None:
        event_type = str(event.get("event_type") or "").strip()
        details = event.get("details") or {}
        if not isinstance(details, dict):
            return None

        if event_type == "program_updated":
            if bool(details.get("alert_suppressed")):
                return None

            external_id = str(
                event.get("program_external_id")
                or details.get("program_external_id")
                or ""
            ).strip()
            program = self.db.get_program(external_id) if external_id else None
            if program and str(program.get("source") or "").casefold().strip() == "vigilseek":
                return None

            title_name, title_platform = self._parse_program_from_event_title(str(event.get("title") or ""))
            name = (str(program.get("name") or "").strip() if program else "") or title_name or external_id or "Unknown"
            platform = (str(program.get("platform") or "").strip() if program else "") or title_platform or "Unknown"
            changed_fields = [str(field).strip() for field in (details.get("changed_fields") or []) if str(field).strip()]
            link = str(details.get("link") or (program.get("link") if program else "") or "").strip()
            reward = str(details.get("reward") or "").strip()
            if not reward and program:
                reward = format_reward_range(program.get("bounty_min"), program.get("bounty_max"))

            message = "\n".join(
                [
                    "[PROGRAM UPDATED]",
                    f"Platform: {platform}",
                    f"Name: {name}",
                    f"Changed: {self._display_changed_fields(changed_fields)}",
                    f"Reward: {reward or 'n/a'}",
                    f"Link: {link or 'n/a'}",
                    f"Program ID: {external_id or 'n/a'}",
                ]
            )
            return (
                event_type,
                message,
                {
                    "platform": platform,
                    "bounty_max": self._as_float(program.get("bounty_max")) if program else None,
                    "text": f"{name} {platform} {link} {' '.join(changed_fields)}",
                },
            )

        if event_type == "github_updated":
            external_id = str(
                event.get("program_external_id")
                or details.get("program_external_id")
                or ""
            ).strip()
            program = self.db.get_program(external_id) if external_id else None
            program_name = str(program.get("name") or "").strip() if program else None
            program_platform = str(program.get("platform") or "").strip() if program else None
            program_bounty_max = self._as_float(program.get("bounty_max")) if program else None

            changed_files_raw = details.get("changed_files") or []
            changed_files: list[dict[str, str]] = []
            if isinstance(changed_files_raw, list):
                for item in changed_files_raw:
                    if not isinstance(item, dict):
                        continue
                    filename = str(item.get("filename") or "").strip()
                    status = str(item.get("status") or "modified").strip()
                    if not filename:
                        continue
                    changed_files.append({"filename": filename, "status": status})

            watch = {
                "repo_owner": str(details.get("repo_owner") or "").strip(),
                "repo_name": str(details.get("repo_name") or "").strip(),
                "file_path": str(details.get("file_path") or "").strip(),
                "branch": str(details.get("requested_branch") or details.get("branch") or "").strip(),
            }
            if not watch["repo_owner"] or not watch["repo_name"]:
                return None

            message = self._build_github_update_message(
                watch=watch,
                old_sha=str(details.get("old_sha") or "").strip(),
                new_sha=str(details.get("new_sha") or "").strip(),
                html_url=str(details.get("html_url") or "").strip(),
                program_name=program_name,
                changed_files=changed_files,
                observed_branch=str(details.get("branch") or watch["branch"]).strip() or None,
            )
            return (
                event_type,
                message,
                {
                    "platform": program_platform or "",
                    "bounty_max": program_bounty_max,
                    "text": " ".join(
                        [
                            str(program_name or ""),
                            f"{watch['repo_owner']}/{watch['repo_name']}",
                            watch["file_path"],
                            ", ".join(item.get("filename", "") for item in changed_files[:10]),
                        ]
                    ),
                },
            )

        return None

    def retry_pending_notifications(self, trigger: str = "scheduler") -> dict[str, Any]:
        if not (self.notifier.enabled or self.github_notifier.enabled):
            summary = {
                "status": "skipped",
                "trigger": trigger,
                "reason": "telegram not configured",
                "candidate_events": 0,
                "reviewed": 0,
                "attempted": 0,
                "sent": 0,
                "skipped": 0,
            }
            self._set_last_status("last_notification_retry_run", summary)
            return summary

        if not self._notification_lock.acquire(blocking=False):
            return {
                "status": "skipped",
                "trigger": trigger,
                "reason": "notification retry already in progress",
            }

        started_dt = datetime.now(timezone.utc)
        started_at = started_dt.isoformat()
        retry_before = (started_dt - timedelta(seconds=NOTIFICATION_RETRY_MIN_AGE_SECONDS)).isoformat()
        reviewed = 0
        attempted = 0
        sent = 0
        skipped = 0

        try:
            events = self.db.list_unnotified_events(
                limit=NOTIFICATION_RETRY_CANDIDATE_LIMIT,
                event_types=NOTIFICATION_RETRY_EVENT_TYPES,
                before_created_at=retry_before,
            )

            for event in reversed(events):
                if attempted >= NOTIFICATION_RETRY_SEND_LIMIT or self._shutdown_requested():
                    break
                reviewed += 1

                payload = self._notification_payload_from_event(event)
                if payload is None:
                    skipped += 1
                    continue

                event_type, message, context = payload
                if not self._should_send_immediate_alert(event_type=event_type, context=context):
                    skipped += 1
                    continue

                attempted += 1
                channel = (
                    NOTIFICATION_CHANNEL_GITHUB
                    if event_type == "github_updated"
                    else NOTIFICATION_CHANNEL_DEFAULT
                )
                if self._safe_send_notification(message, channel=channel):
                    sent += 1
                    self.db.mark_event_notified(int(event["id"]))

            summary = {
                "status": "stopped" if self._shutdown_requested() else "ok",
                "trigger": trigger,
                "started_at": started_at,
                "retry_before": retry_before,
                "candidate_events": len(events),
                "reviewed": reviewed,
                "attempted": attempted,
                "sent": sent,
                "skipped": skipped,
            }
            self._set_last_status("last_notification_retry_run", summary)
            return summary
        except Exception as exc:
            masked_error = self._mask_secrets(str(exc))
            summary = {
                "status": "error",
                "trigger": trigger,
                "started_at": started_at,
                "error": masked_error,
                "candidate_events": 0,
                "reviewed": reviewed,
                "attempted": attempted,
                "sent": sent,
                "skipped": skipped,
            }
            self.db.insert_event(
                event_type="run_error",
                title="notification retry failed",
                details=summary,
                created_at=started_at,
                notified=False,
            )
            self._set_last_status("last_notification_retry_run", summary)
            return summary
        finally:
            self._notification_lock.release()

    def _maybe_add_watch_from_program_link(self, program: dict[str, Any], now_iso: str) -> None:
        link = program.get("link") or ""
        parsed = parse_github_url(link)
        if not parsed:
            return
        owner, repo, file_path, branch = parsed
        self.db.add_github_watch(
            program_external_id=program["external_id"],
            repo_owner=owner,
            repo_name=repo,
            file_path=file_path,
            branch=branch,
            metadata={"source": "program_link"},
            now_iso=now_iso,
        )

    def scan_bbradar(self, trigger: str = "scheduler") -> dict[str, Any]:
        if not self._bbradar_lock.acquire(blocking=False):
            return {
                "status": "skipped",
                "reason": "scan already in progress",
                "trigger": trigger,
            }

        started_at = utc_now_iso()
        created = 0
        updated = 0
        unchanged = 0
        notifications = 0

        try:
            bootstrap_mode = self.db.count_programs() == 0
            source_items: list[tuple[str, dict[str, Any]]] = [
                ("bbradar", item) for item in self.bbradar_client.fetch_programs()
            ]

            if self.vigilseek_client is not None:
                try:
                    source_items.extend(
                        ("vigilseek", item) for item in self.vigilseek_client.fetch_programs()
                    )
                except VigilSeekClientError as exc:
                    if self._shutdown_requested():
                        summary = {
                            "status": "stopped",
                            "trigger": trigger,
                            "started_at": started_at,
                            "tracked_programs": 0,
                            "created": created,
                            "updated": updated,
                            "unchanged": unchanged,
                            "notifications": notifications,
                        }
                        self._set_last_status("last_bbradar_run", summary)
                        return summary
                    masked_error = self._mask_secrets(str(exc))
                    self.db.insert_event(
                        event_type="run_error",
                        title="vigilseek scan failed",
                        details={
                            "trigger": trigger,
                            "started_at": started_at,
                            "error": masked_error,
                        },
                        created_at=started_at,
                        notified=False,
                    )
                    self._maybe_send_source_health_alert(source="vigilseek", error=masked_error)

            existing_programs = self.db.list_programs(limit=100000, focus="all")
            existing_external_ids = {
                str(program.get("external_id") or "").casefold()
                for program in existing_programs
                if program.get("external_id")
            }
            existing_links = {
                normalized
                for normalized in (
                    self._normalize_link(program.get("link")) for program in existing_programs
                )
                if normalized
            }
            existing_platform_name = {
                self._program_identity_key(
                    str(program.get("platform") or ""),
                    str(program.get("name") or ""),
                )
                for program in existing_programs
            }

            filtered: list[dict[str, Any]] = []
            for source, item in source_items:
                if self._shutdown_requested():
                    break
                try:
                    normalized = self._normalize_program(item, source=source)
                except ValueError:
                    continue

                if not self._matches_filters(normalized):
                    continue

                if source == "vigilseek" and self._is_duplicate_program(
                    normalized=normalized,
                    external_ids=existing_external_ids,
                    links=existing_links,
                    platform_name_keys=existing_platform_name,
                ):
                    continue

                filtered.append(normalized)

                existing_external_ids.add(str(normalized.get("external_id") or "").casefold())
                normalized_link = self._normalize_link(normalized.get("link"))
                if normalized_link:
                    existing_links.add(normalized_link)
                existing_platform_name.add(
                    self._program_identity_key(
                        str(normalized.get("platform") or ""),
                        str(normalized.get("name") or ""),
                    )
                )

            for normalized in filtered:
                if self._shutdown_requested():
                    break
                action, changed_fields, field_diffs = self.db.upsert_program(normalized, started_at)
                should_notify_program_event = normalized.get("source") != "vigilseek"
                program_text = " ".join(
                    [
                        str(normalized.get("name") or ""),
                        str(normalized.get("platform") or ""),
                        str(normalized.get("scope_type") or ""),
                        str(normalized.get("link") or ""),
                    ]
                )

                if action == "created":
                    created += 1
                    self._maybe_add_watch_from_program_link(normalized, started_at)

                    if bootstrap_mode and not self.settings.bootstrap_notify_existing:
                        continue

                    event_id = self.db.insert_event(
                        event_type="new_program",
                        title=f"New program: {normalized['name']} ({normalized['platform']})",
                        details={
                            "program_external_id": normalized["external_id"],
                            "platform": normalized["platform"],
                            "name": normalized["name"],
                            "link": normalized["link"],
                            "date_launched": normalized["date_launched"],
                            "reward": format_reward_range(normalized["bounty_min"], normalized["bounty_max"]),
                        },
                        created_at=started_at,
                        program_external_id=normalized["external_id"],
                    )

                    can_notify = should_notify_program_event and self._should_send_immediate_alert(
                        event_type="new_program",
                        context={
                            "platform": normalized.get("platform"),
                            "bounty_max": normalized.get("bounty_max"),
                            "text": program_text,
                        },
                    )
                    if can_notify and self._safe_send_notification(self._build_new_program_message(normalized)):
                        notifications += 1
                        self.db.mark_event_notified(event_id)

                elif action == "updated":
                    updated += 1
                    noisy_immunefi_bounty_min_update = self._is_noisy_immunefi_bounty_min_update(
                        platform=str(normalized.get("platform") or ""),
                        changed_fields=changed_fields,
                        field_diffs=field_diffs,
                    )
                    event_id = self.db.insert_event(
                        event_type="program_updated",
                        title=f"Program updated: {normalized['name']} ({normalized['platform']})",
                        details={
                            "program_external_id": normalized["external_id"],
                            "changed_fields": changed_fields,
                            "field_diffs": field_diffs,
                            "link": normalized["link"],
                            "reward": format_reward_range(normalized["bounty_min"], normalized["bounty_max"]),
                            "alert_suppressed": noisy_immunefi_bounty_min_update,
                            "alert_suppressed_reason": (
                                "noisy_immunefi_bounty_min_flip" if noisy_immunefi_bounty_min_update else ""
                            ),
                        },
                        created_at=started_at,
                        program_external_id=normalized["external_id"],
                    )

                    can_notify = (
                        should_notify_program_event
                        and not noisy_immunefi_bounty_min_update
                        and self._should_send_immediate_alert(
                            event_type="program_updated",
                            context={
                                "platform": normalized.get("platform"),
                                "bounty_max": normalized.get("bounty_max"),
                                "text": f"{program_text} {' '.join(changed_fields)}",
                            },
                        )
                    )
                    if can_notify and self._safe_send_notification(
                        self._build_program_updated_message(normalized, changed_fields)
                    ):
                        notifications += 1
                        self.db.mark_event_notified(event_id)
                else:
                    unchanged += 1

            if (
                not self._shutdown_requested()
                and bootstrap_mode
                and created > 0
                and not self.settings.bootstrap_notify_existing
            ):
                self.db.insert_event(
                    event_type="bootstrap_seed",
                    title=f"Initial seed completed for {created} program(s)",
                    details={
                        "created": created,
                        "trigger": trigger,
                        "note": "Initial data was seeded without sending Telegram alerts.",
                    },
                    created_at=started_at,
                    notified=False,
                )

            summary = {
                "status": "stopped" if self._shutdown_requested() else "ok",
                "trigger": trigger,
                "started_at": started_at,
                "tracked_programs": len(filtered),
                "created": created,
                "updated": updated,
                "unchanged": unchanged,
                "notifications": notifications,
            }
            self._set_last_status("last_bbradar_run", summary)
            return summary

        except BBRadarClientError as exc:
            if self._shutdown_requested():
                summary = {
                    "status": "stopped",
                    "trigger": trigger,
                    "started_at": started_at,
                    "tracked_programs": 0,
                    "created": created,
                    "updated": updated,
                    "unchanged": unchanged,
                    "notifications": notifications,
                }
                self._set_last_status("last_bbradar_run", summary)
                return summary
            masked_error = self._mask_secrets(str(exc))
            summary = {
                "status": "error",
                "trigger": trigger,
                "started_at": started_at,
                "error": masked_error,
            }
            self.db.insert_event(
                event_type="run_error",
                title="bbradar scan failed",
                details=summary,
                created_at=started_at,
                notified=False,
            )
            self._maybe_send_source_health_alert(source="bbradar", error=masked_error)
            self._set_last_status("last_bbradar_run", summary)
            return summary
        finally:
            self._bbradar_lock.release()

    def scan_github(self, trigger: str = "scheduler") -> dict[str, Any]:
        if not self._github_lock.acquire(blocking=False):
            with self._status_lock:
                running_status = dict(self._status.get("last_github_run") or {})
            if running_status.get("status") == "running":
                running_status["reason"] = "scan already in progress"
                return running_status
            return {
                "status": "skipped",
                "reason": "scan already in progress",
                "trigger": trigger,
            }

        started_at = utc_now_iso()
        changed = 0
        unchanged = 0
        baseline = 0
        errors = 0
        notifications = 0
        rate_limited = False

        try:
            watches = self.db.list_github_watches(active_only=True)
            self._set_last_status(
                "last_github_run",
                {
                    "status": "running",
                    "trigger": trigger,
                    "started_at": started_at,
                    "tracked_watches": len(watches),
                    "changed": 0,
                    "unchanged": 0,
                    "baseline": 0,
                    "errors": 0,
                    "notifications": 0,
                    "rate_limited": False,
                },
            )
            for watch in watches:
                if self._shutdown_requested():
                    break
                try:
                    state = self.github_client.fetch_target_state(
                        owner=watch["repo_owner"],
                        repo=watch["repo_name"],
                        file_path=watch["file_path"],
                        branch=watch["branch"],
                    )
                except GitHubClientError as exc:
                    if self._shutdown_requested():
                        break
                    errors += 1
                    masked_error = self._mask_secrets(str(exc))
                    self.db.insert_event(
                        event_type="run_error",
                        title="GitHub watch check failed",
                        details={
                            "watch_id": watch["id"],
                            "repo_owner": watch["repo_owner"],
                            "repo_name": watch["repo_name"],
                            "file_path": watch["file_path"],
                            "branch": watch["branch"],
                            "error": masked_error,
                        },
                        created_at=started_at,
                    )
                    self._maybe_send_source_health_alert(source="github", error=masked_error)
                    if self._is_rate_limit_error(exc):
                        rate_limited = True
                        break
                    continue

                previous_sha = watch.get("last_sha")
                new_sha = state["sha"]
                effective_branch = state.get("resolved_branch") or watch["branch"]
                if self._shutdown_requested():
                    break
                self.db.update_github_watch_state(watch_id=watch["id"], last_sha=new_sha, now_iso=started_at)

                if not previous_sha:
                    baseline += 1
                    continue

                if previous_sha == new_sha:
                    unchanged += 1
                    continue

                changed += 1
                changed_files: list[dict[str, str]] = []
                if watch.get("file_path"):
                    changed_files = [
                        {
                            "filename": str(watch["file_path"]),
                            "status": "tracked_path_changed",
                        }
                    ]
                else:
                    try:
                        changed_files = self.github_client.fetch_commit_changed_files(
                            owner=watch["repo_owner"],
                            repo=watch["repo_name"],
                            old_sha=previous_sha,
                            new_sha=new_sha,
                            max_files=25,
                        )
                    except GitHubClientError:
                        changed_files = []

                program_name: str | None = None
                program_platform: str | None = None
                program_bounty_max: float | None = None
                if watch.get("program_external_id"):
                    program = self.db.get_program(watch["program_external_id"])
                    if program:
                        program_name = str(program.get("name") or "")
                        program_platform = str(program.get("platform") or "")
                        program_bounty_max = self._as_float(program.get("bounty_max"))

                event_id = self.db.insert_event(
                    event_type="github_updated",
                    title=f"GitHub updated: {watch['repo_owner']}/{watch['repo_name']}",
                    details={
                        "watch_id": watch["id"],
                        "repo_owner": watch["repo_owner"],
                        "repo_name": watch["repo_name"],
                        "file_path": watch["file_path"],
                        "branch": effective_branch,
                        "requested_branch": watch["branch"],
                        "old_sha": previous_sha,
                        "new_sha": new_sha,
                        "html_url": state["html_url"],
                        "changed_files": changed_files,
                        "program_external_id": watch.get("program_external_id"),
                    },
                    created_at=started_at,
                    program_external_id=watch.get("program_external_id"),
                )

                message = self._build_github_update_message(
                    watch=watch,
                    old_sha=previous_sha,
                    new_sha=new_sha,
                    html_url=state["html_url"],
                    program_name=program_name,
                    changed_files=changed_files,
                    observed_branch=effective_branch,
                )
                context_text = " ".join(
                    [
                        str(program_name or ""),
                        f"{watch.get('repo_owner')}/{watch.get('repo_name')}",
                        str(watch.get("file_path") or ""),
                        ", ".join(str(item.get("filename") or "") for item in changed_files[:10]),
                    ]
                )
                can_notify = self._should_send_immediate_alert(
                    event_type="github_updated",
                    context={
                        "platform": program_platform or "",
                        "bounty_max": program_bounty_max,
                        "text": context_text,
                    },
                )
                if can_notify and self._safe_send_notification(message, channel=NOTIFICATION_CHANNEL_GITHUB):
                    notifications += 1
                    self.db.mark_event_notified(event_id)

            summary = {
                "status": "stopped" if self._shutdown_requested() else "ok",
                "trigger": trigger,
                "started_at": started_at,
                "tracked_watches": len(watches),
                "changed": changed,
                "unchanged": unchanged,
                "baseline": baseline,
                "errors": errors,
                "notifications": notifications,
                "rate_limited": rate_limited,
            }
            self._set_last_status("last_github_run", summary)
            return summary

        except Exception as exc:  # pragma: no cover - defensive runtime handling
            if self._shutdown_requested():
                summary = {
                    "status": "stopped",
                    "trigger": trigger,
                    "started_at": started_at,
                    "tracked_watches": 0,
                    "changed": changed,
                    "unchanged": unchanged,
                    "baseline": baseline,
                    "errors": errors,
                    "notifications": notifications,
                    "rate_limited": rate_limited,
                }
                self._set_last_status("last_github_run", summary)
                return summary
            masked_error = self._mask_secrets(str(exc))
            summary = {
                "status": "error",
                "trigger": trigger,
                "started_at": started_at,
                "error": masked_error,
            }
            self.db.insert_event(
                event_type="run_error",
                title="github scan failed",
                details=summary,
                created_at=started_at,
            )
            self._maybe_send_source_health_alert(source="github", error=masked_error)
            self._set_last_status("last_github_run", summary)
            return summary
        finally:
            self._github_lock.release()

    def cleanup_invalid_github_watches(
        self,
        *,
        min_errors: int = 2,
        lookback_hours: int = 24 * 14,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        min_errors = max(1, min_errors)
        lookback_hours = max(1, lookback_hours)

        now_iso = utc_now_iso()
        now_dt = self._parse_utc_iso(now_iso) or datetime.now(timezone.utc)
        cutoff_dt = now_dt - timedelta(hours=lookback_hours)

        active_watches = self.db.list_github_watches(active_only=True)
        active_by_id = {int(watch["id"]): watch for watch in active_watches}

        error_events = self.db.list_events(limit=10000, event_type="run_error")
        not_found_counts: dict[int, int] = {}
        latest_error_by_watch: dict[int, str] = {}

        for event in error_events:
            event_dt = self._parse_utc_iso(str(event.get("created_at") or ""))
            if not event_dt or event_dt < cutoff_dt:
                continue

            details = event.get("details") or {}
            watch_id_raw = details.get("watch_id")
            if watch_id_raw is None:
                continue

            try:
                watch_id = int(watch_id_raw)
            except (TypeError, ValueError):
                continue

            if watch_id not in active_by_id:
                continue

            error_text = str(details.get("error") or "")
            if not self._is_not_found_watch_error(error_text):
                continue

            not_found_counts[watch_id] = not_found_counts.get(watch_id, 0) + 1
            latest_error_by_watch[watch_id] = error_text

        candidates = []
        for watch_id, count in sorted(not_found_counts.items(), key=lambda item: item[1], reverse=True):
            if count < min_errors:
                continue
            watch = active_by_id[watch_id]
            candidates.append(
                {
                    "watch_id": watch_id,
                    "repo_owner": watch["repo_owner"],
                    "repo_name": watch["repo_name"],
                    "file_path": watch["file_path"],
                    "branch": watch["branch"],
                    "error_count": count,
                    "latest_error": latest_error_by_watch.get(watch_id, ""),
                }
            )

        deactivated: list[dict[str, Any]] = []
        if not dry_run:
            for candidate in candidates:
                if self.db.deactivate_github_watch(candidate["watch_id"], now_iso=now_iso):
                    deactivated.append(candidate)

            if deactivated:
                self.db.insert_event(
                    event_type="maintenance_cleanup",
                    title=f"Deactivated {len(deactivated)} invalid GitHub watch(es)",
                    details={
                        "trigger": "maintenance",
                        "dry_run": False,
                        "min_errors": min_errors,
                        "lookback_hours": lookback_hours,
                        "deactivated_watch_ids": [item["watch_id"] for item in deactivated],
                    },
                    created_at=now_iso,
                )

        return {
            "status": "ok",
            "dry_run": dry_run,
            "min_errors": min_errors,
            "lookback_hours": lookback_hours,
            "active_watches_total": len(active_watches),
            "candidate_count": len(candidates),
            "deactivated_count": len(deactivated),
            "candidates": candidates,
            "deactivated": deactivated,
            "cutoff": cutoff_dt.isoformat(),
            "evaluated_at": now_iso,
        }

    def create_github_watch(
        self,
        *,
        github_url: str | None,
        owner: str | None,
        repo: str | None,
        file_path: str,
        branch: str,
        program_external_id: str | None,
    ) -> dict[str, Any]:
        if github_url:
            parsed = parse_github_url(github_url)
            if not parsed:
                raise ValueError("unsupported GitHub URL")
            owner, repo, parsed_path, parsed_branch = parsed
            if not file_path:
                file_path = parsed_path
            if branch == "main" and parsed_branch:
                branch = parsed_branch

        if not owner or not repo:
            raise ValueError("owner and repo are required")

        now_iso = utc_now_iso()
        watch = self.db.add_github_watch(
            program_external_id=program_external_id,
            repo_owner=owner,
            repo_name=repo,
            file_path=file_path,
            branch=branch,
            metadata={"source": "manual" if not github_url else "github_url"},
            now_iso=now_iso,
        )

        try:
            state = self.github_client.fetch_target_state(
                owner=watch["repo_owner"],
                repo=watch["repo_name"],
                file_path=watch["file_path"],
                branch=watch["branch"],
            )
            self.db.update_github_watch_state(watch["id"], state["sha"], now_iso)
            watch["last_sha"] = state["sha"]
            watch["last_checked_at"] = now_iso
            if state.get("resolved_branch"):
                watch["resolved_branch"] = state["resolved_branch"]
        except GitHubClientError as exc:
            watch["bootstrap_error"] = str(exc)

        return watch

    def create_submission(self, payload: dict[str, Any]) -> dict[str, Any]:
        report_path = payload.get("report_pdf_path")
        if report_path and not payload.get("pdf_summary"):
            payload["pdf_summary"] = extract_pdf_summary(report_path)

        duplicate_candidates = self.find_submission_duplicates(payload, limit=5)
        if payload.get("block_on_duplicate") and duplicate_candidates:
            raise ValueError("potential duplicate submission detected")

        now_iso = utc_now_iso()
        created = self.db.create_submission(payload, now_iso)
        self.db.ensure_submission_workflow(int(created["id"]), now_iso=now_iso)

        due_at = payload.get("due_at")
        sla_hours = payload.get("sla_hours")
        if due_at or sla_hours:
            self.set_submission_deadline(
                submission_id=int(created["id"]),
                due_at=str(due_at) if due_at else None,
                sla_hours=int(sla_hours) if sla_hours is not None else None,
                remind_before_minutes=int(payload.get("remind_before_minutes") or 60),
                active=True,
            )
        created["duplicate_candidates"] = duplicate_candidates
        return created

    def update_submission(self, submission_id: int, updates: dict[str, Any]) -> dict[str, Any] | None:
        report_path = updates.get("report_pdf_path")
        if report_path and "pdf_summary" not in updates:
            updates["pdf_summary"] = extract_pdf_summary(report_path)

        now_iso = utc_now_iso()
        return self.db.update_submission(submission_id, updates, now_iso)

    def get_program_timeline(self, external_id: str, limit: int = 120) -> list[dict[str, Any]]:
        events = self.db.list_program_events(external_id=external_id, limit=max(1, limit))
        timeline: list[dict[str, Any]] = []
        for event in events:
            details = event.get("details") or {}
            entry = {
                "id": event.get("id"),
                "created_at": event.get("created_at"),
                "event_type": event.get("event_type"),
                "title": event.get("title"),
                "changed_fields": details.get("changed_fields") or [],
                "field_diffs": details.get("field_diffs") or {},
                "changed_files": details.get("changed_files") or [],
                "link": details.get("link") or details.get("html_url"),
                "branch": details.get("branch"),
            }
            timeline.append(entry)
        timeline.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return timeline

    def upsert_program_tag(
        self,
        *,
        program_external_id: str,
        tag: str,
        note: str | None = None,
        manual_boost: float = 0.0,
        created_by: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "program_external_id": program_external_id.strip(),
            "tag": tag.strip().casefold(),
            "note": note,
            "manual_boost": float(manual_boost or 0.0),
            "created_by": created_by,
        }
        return self.db.upsert_program_tag(payload, now_iso=utc_now_iso())

    def list_program_tags(
        self,
        *,
        program_external_id: str | None = None,
        tag: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.db.list_program_tags(program_external_id=program_external_id, tag=tag)

    def delete_program_tag(self, tag_id: int) -> bool:
        return self.db.delete_program_tag(tag_id)

    def list_hotlist_programs(
        self,
        *,
        limit: int = 100,
        focus: str = "smart_contract",
        q: str | None = None,
    ) -> list[dict[str, Any]]:
        programs = self.list_programs_with_priority(limit=2000, focus=focus, q=q)
        tag_rows = self.db.list_program_tags()
        by_program: dict[str, list[dict[str, Any]]] = {}
        for row in tag_rows:
            external_id = str(row.get("program_external_id") or "")
            by_program.setdefault(external_id, []).append(row)

        hotlist: list[dict[str, Any]] = []
        for program in programs:
            tags = by_program.get(str(program.get("external_id") or ""), [])
            if not tags:
                continue
            manual_boost = sum(float(tag.get("manual_boost") or 0.0) for tag in tags)
            score = min(100.0, float(program.get("priority_score") or 0.0) + manual_boost)
            item = dict(program)
            item["hotlist_tags"] = tags
            item["hotlist_score"] = round(score, 2)
            hotlist.append(item)
        hotlist.sort(key=lambda item: float(item.get("hotlist_score") or 0.0), reverse=True)
        return hotlist[: max(1, limit)]

    @staticmethod
    def _submission_reason_categories(text: str) -> list[str]:
        lowered = str(text or "").casefold()
        categories: list[str] = []
        for category, keywords in INTELLIGENCE_KEYWORDS.items():
            if any(keyword in lowered for keyword in keywords):
                categories.append(category)
        if not categories and lowered.strip():
            categories.append("other")
        return categories

    def get_submission_intelligence(self, months: int = 6) -> dict[str, Any]:
        submissions = self.db.list_submissions(limit=10000)
        now_dt = datetime.now(timezone.utc)
        cutoff = now_dt - timedelta(days=max(1, months) * 31)

        category_counter: Counter[str] = Counter()
        monthly_counter: Counter[str] = Counter()
        duplicate_candidates: list[dict[str, Any]] = []

        for item in submissions:
            status = str(item.get("status") or "").casefold()
            reason_blob = " ".join(
                [
                    str(item.get("rejection_reason") or ""),
                    str(item.get("triage_notes") or ""),
                ]
            )
            if status == "rejected" or reason_blob.strip():
                for category in self._submission_reason_categories(reason_blob):
                    category_counter[category] += 1

            updated_dt = self._parse_utc_iso(str(item.get("updated_at") or ""))
            if updated_dt and updated_dt >= cutoff:
                month_key = updated_dt.strftime("%Y-%m")
                monthly_counter[month_key] += 1

        # Sample duplicate-risk list using title/body similarity against existing reports.
        for item in submissions[:200]:
            matches = self.find_submission_duplicates(item, limit=2, skip_submission_id=int(item.get("id") or 0))
            if matches:
                duplicate_candidates.append(
                    {
                        "submission_id": item.get("id"),
                        "program_name": item.get("program_name"),
                        "bug_title": item.get("bug_title"),
                        "matches": matches,
                    }
                )

        monthly_rows = [
            {"month": key, "count": monthly_counter[key]}
            for key in sorted(monthly_counter.keys())
        ]

        return {
            "total_submissions": len(submissions),
            "categories": [
                {"category": key, "count": value}
                for key, value in category_counter.most_common()
            ],
            "monthly_trend": monthly_rows,
            "duplicate_risk_samples": duplicate_candidates[:20],
        }

    @staticmethod
    def _normalize_similarity_text(payload: dict[str, Any]) -> str:
        chunks = [
            str(payload.get("platform") or ""),
            str(payload.get("program_name") or ""),
            str(payload.get("bug_title") or ""),
            str(payload.get("triage_notes") or ""),
            str(payload.get("rejection_reason") or ""),
        ]
        text = " ".join(chunks).casefold()
        text = re.sub(r"[^a-z0-9\s]+", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def find_submission_duplicates(
        self,
        payload: dict[str, Any],
        *,
        limit: int = 5,
        threshold: float = 0.57,
        skip_submission_id: int | None = None,
    ) -> list[dict[str, Any]]:
        candidate_text = self._normalize_similarity_text(payload)
        if not candidate_text:
            return []
        submissions = self.db.list_submissions(limit=10000)
        matches: list[dict[str, Any]] = []
        for item in submissions:
            item_id = int(item.get("id") or 0)
            if skip_submission_id and item_id == skip_submission_id:
                continue
            reference_text = self._normalize_similarity_text(item)
            if not reference_text:
                continue
            score = difflib.SequenceMatcher(None, candidate_text, reference_text).ratio()
            same_program = str(item.get("program_name") or "").casefold().strip() == str(
                payload.get("program_name") or ""
            ).casefold().strip()
            score_boosted = score + (0.08 if same_program else 0.0)
            if score_boosted < threshold:
                continue
            matches.append(
                {
                    "submission_id": item_id,
                    "program_name": item.get("program_name"),
                    "bug_title": item.get("bug_title"),
                    "status": item.get("status"),
                    "similarity": round(score_boosted, 3),
                    "updated_at": item.get("updated_at"),
                }
            )
        matches.sort(key=lambda item: float(item.get("similarity") or 0.0), reverse=True)
        return matches[: max(1, limit)]

    def list_report_templates(self) -> list[dict[str, Any]]:
        return list(REPORT_TEMPLATES.values())

    def get_report_template(self, platform: str) -> dict[str, Any]:
        key = str(platform or "").casefold().strip()
        return REPORT_TEMPLATES.get(
            key,
            {
                "platform": platform,
                "sections": ["Summary", "Impact", "Proof of Concept", "Mitigation"],
                "checklist": ["Describe root cause", "Describe impact", "Provide reproducible steps"],
            },
        )

    def validate_report_template(self, platform: str, report_text: str) -> dict[str, Any]:
        template = self.get_report_template(platform)
        text = str(report_text or "")
        lowered = text.casefold()
        missing_sections = [
            section for section in template.get("sections", []) if str(section).casefold() not in lowered
        ]
        checklist = template.get("checklist", [])
        checklist_hits = []
        for item in checklist:
            token = str(item).casefold().split(" ")[0]
            checklist_hits.append(token and token in lowered)
        coverage = 0.0
        total_checks = len(template.get("sections", [])) + len(checklist_hits)
        covered = (len(template.get("sections", [])) - len(missing_sections)) + sum(1 for hit in checklist_hits if hit)
        if total_checks > 0:
            coverage = covered / total_checks
        return {
            "platform": template.get("platform"),
            "missing_sections": missing_sections,
            "checklist_hits": checklist_hits,
            "score": round(coverage * 100, 2),
            "valid": len(missing_sections) == 0,
        }

    @staticmethod
    def _normalize_pre_audit_status(value: str | None, default: str = "new") -> str:
        status = str(value or default).casefold().strip().replace(" ", "_")
        if status not in PRE_AUDIT_FINDING_STATUSES:
            raise ValueError(f"invalid status: {status}")
        return status

    @staticmethod
    def _normalize_tags(value: Any) -> list[str]:
        if isinstance(value, list):
            raw = value
        elif isinstance(value, str):
            raw = [part.strip() for part in value.split(",")]
        else:
            raw = []
        tags = [str(item).strip().casefold() for item in raw if str(item).strip()]
        return tags[:30]

    @staticmethod
    def _normalize_confidence(value: Any) -> float | None:
        if value is None or value == "":
            return None
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return None
        return max(0.0, min(1.0, confidence))

    def _resolve_program_context(
        self,
        *,
        program_external_id: str | None,
        platform: str | None,
        program_name: str | None,
    ) -> tuple[str | None, str | None, str | None]:
        external_id = str(program_external_id or "").strip() or None
        platform_text = str(platform or "").strip() or None
        program_text = str(program_name or "").strip() or None
        if external_id:
            program = self.db.get_program(external_id)
            if program:
                if not platform_text:
                    platform_text = str(program.get("platform") or "").strip() or None
                if not program_text:
                    program_text = str(program.get("name") or "").strip() or None
        return external_id, platform_text, program_text

    def create_pre_audit_finding(
        self,
        payload: dict[str, Any],
        *,
        actor_user_id: int | None = None,
        actor_username: str | None = None,
    ) -> dict[str, Any]:
        title = str(payload.get("title") or "").strip()
        description = str(payload.get("description") or "").strip()
        if not title:
            raise ValueError("title is required")
        if not description:
            raise ValueError("description is required")

        external_id, platform, program_name = self._resolve_program_context(
            program_external_id=(payload.get("program_external_id") if payload.get("program_external_id") else None),
            platform=(payload.get("platform") if payload.get("platform") else None),
            program_name=(payload.get("program_name") if payload.get("program_name") else None),
        )

        now_iso = utc_now_iso()
        severity = str(payload.get("severity") or "medium").casefold().strip() or "medium"
        status = self._normalize_pre_audit_status(str(payload.get("status") or "new"))
        source = str(payload.get("source") or "codex_chatgpt").strip() or "codex_chatgpt"
        target_github_url = str(payload.get("target_github_url") or "").strip() or None
        source_reference = str(payload.get("source_reference") or "").strip() or None
        category = str(payload.get("category") or "").strip() or None
        impact = str(payload.get("impact") or "").strip() or None
        poc_steps = str(payload.get("poc_steps") or "").strip() or None
        recommendation = str(payload.get("recommendation") or "").strip() or None

        created = self.db.create_pre_audit_finding(
            {
                "program_external_id": external_id,
                "platform": platform,
                "program_name": program_name,
                "title": title,
                "severity": severity,
                "status": status,
                "category": category,
                "description": description,
                "impact": impact,
                "poc_steps": poc_steps,
                "recommendation": recommendation,
                "source": source,
                "source_reference": source_reference,
                "target_github_url": target_github_url,
                "ai_confidence": self._normalize_confidence(payload.get("ai_confidence")),
                "tags": self._normalize_tags(payload.get("tags")),
                "created_by_user_id": actor_user_id,
                "created_by_username": actor_username,
            },
            now_iso=now_iso,
        )
        self.db.insert_event(
            event_type="pre_audit_finding_created",
            title=f"Pre-audit finding #{created['id']} created",
            details={
                "finding_id": created["id"],
                "status": created.get("status"),
                "severity": created.get("severity"),
                "program_external_id": created.get("program_external_id"),
                "platform": created.get("platform"),
                "program_name": created.get("program_name"),
            },
            created_at=now_iso,
            program_external_id=created.get("program_external_id"),
            notified=False,
        )
        created["duplicate_candidates"] = self.find_submission_duplicates(
            {
                "platform": created.get("platform"),
                "program_name": created.get("program_name"),
                "bug_title": created.get("title"),
                "triage_notes": created.get("description"),
                "rejection_reason": created.get("impact"),
            },
            limit=5,
        )
        return created

    def list_pre_audit_findings(
        self,
        *,
        limit: int = 200,
        status: str | None = None,
        platform: str | None = None,
        program_external_id: str | None = None,
        q: str | None = None,
    ) -> list[dict[str, Any]]:
        normalized_status = None
        if status and status.strip():
            normalized_status = self._normalize_pre_audit_status(status)
        return self.db.list_pre_audit_findings(
            limit=max(1, limit),
            status=normalized_status,
            platform=platform,
            program_external_id=program_external_id,
            q=q,
        )

    def get_pre_audit_finding_detail(self, finding_id: int) -> dict[str, Any] | None:
        finding = self.db.get_pre_audit_finding(finding_id)
        if finding is None:
            return None
        duplicate_candidates = self.find_submission_duplicates(
            {
                "platform": finding.get("platform"),
                "program_name": finding.get("program_name"),
                "bug_title": finding.get("title"),
                "triage_notes": finding.get("description"),
                "rejection_reason": finding.get("impact"),
            },
            limit=8,
        )
        template = self.get_report_template(str(finding.get("platform") or ""))
        return {
            "finding": finding,
            "duplicate_candidates": duplicate_candidates,
            "report_template": template,
        }

    def update_pre_audit_finding(
        self,
        finding_id: int,
        updates: dict[str, Any],
        *,
        actor_user_id: int | None = None,
        actor_username: str | None = None,
    ) -> dict[str, Any] | None:
        existing = self.db.get_pre_audit_finding(finding_id)
        if existing is None:
            return None
        clean = dict(updates)
        if "status" in clean and clean.get("status") is not None:
            clean["status"] = self._normalize_pre_audit_status(str(clean.get("status")))

        if "title" in clean and not str(clean.get("title") or "").strip():
            raise ValueError("title cannot be empty")
        if "description" in clean and not str(clean.get("description") or "").strip():
            raise ValueError("description cannot be empty")

        if "tags" in clean:
            clean["tags"] = self._normalize_tags(clean.get("tags"))
        if "ai_confidence" in clean:
            clean["ai_confidence"] = self._normalize_confidence(clean.get("ai_confidence"))

        if "program_external_id" in clean:
            ext, platform, program_name = self._resolve_program_context(
                program_external_id=(clean.get("program_external_id") if clean.get("program_external_id") else None),
                platform=(clean.get("platform") if clean.get("platform") else existing.get("platform")),
                program_name=(clean.get("program_name") if clean.get("program_name") else existing.get("program_name")),
            )
            clean["program_external_id"] = ext
            if "platform" not in clean:
                clean["platform"] = platform
            if "program_name" not in clean:
                clean["program_name"] = program_name

        now_iso = utc_now_iso()
        next_status = str(clean.get("status") or existing.get("status") or "")
        if next_status == "validated":
            clean["validated_by_user_id"] = actor_user_id
            clean["validated_by_username"] = actor_username
            clean["validated_at"] = now_iso

        updated = self.db.update_pre_audit_finding(finding_id=finding_id, updates=clean, now_iso=now_iso)
        if updated is None:
            return None

        previous_status = str(existing.get("status") or "")
        if updated.get("status") != previous_status:
            self.db.insert_event(
                event_type="pre_audit_finding_status_changed",
                title=f"Pre-audit finding #{finding_id} status changed",
                details={
                    "finding_id": finding_id,
                    "old_status": previous_status,
                    "new_status": updated.get("status"),
                    "actor": actor_username,
                },
                created_at=now_iso,
                program_external_id=updated.get("program_external_id"),
                notified=False,
            )

        return updated

    def _build_pre_audit_report_markdown(self, finding: dict[str, Any]) -> str:
        platform = str(finding.get("platform") or "Unknown")
        template = self.get_report_template(platform)
        sections = template.get("sections", [])
        title = str(finding.get("title") or "Untitled Finding").strip()
        description = str(finding.get("description") or "").strip()
        impact = str(finding.get("impact") or "").strip()
        poc_steps = str(finding.get("poc_steps") or "").strip()
        recommendation = str(finding.get("recommendation") or "").strip()
        source_reference = str(finding.get("source_reference") or "").strip()
        target_github_url = str(finding.get("target_github_url") or "").strip()

        def section_content(section: str) -> str:
            key = str(section).casefold().strip()
            if "title" in key:
                return title
            if "summary" in key:
                return description or "TBD"
            if "root cause" in key:
                return description or "TBD"
            if "impact" in key:
                return impact or "TBD"
            if "proof" in key or "steps" in key or "vulnerability details" in key:
                return poc_steps or description or "TBD"
            if "mitigation" in key or "recommendation" in key:
                return recommendation or "TBD"
            if "tools" in key:
                return "Manual analysis + Codex/ChatGPT-assisted review."
            if "references" in key:
                refs = [value for value in (source_reference, target_github_url) if value]
                return "\n".join(f"- {value}" for value in refs) if refs else "TBD"
            return description or "TBD"

        lines = [
            f"# {title}",
            "",
            f"- Platform: {platform or 'Unknown'}",
            f"- Program: {finding.get('program_name') or 'Unknown'}",
            f"- Severity: {finding.get('severity') or 'unknown'}",
            f"- Finding ID: {finding.get('id')}",
            "",
        ]

        for section in sections:
            lines.append(f"## {section}")
            lines.append(section_content(str(section)))
            lines.append("")

        return "\n".join(lines).strip()

    def generate_pre_audit_report(
        self,
        finding_id: int,
        *,
        actor_user_id: int | None = None,
        actor_username: str | None = None,
        create_submission_draft: bool = False,
    ) -> dict[str, Any]:
        finding = self.db.get_pre_audit_finding(finding_id)
        if finding is None:
            raise ValueError("finding not found")

        current_status = str(finding.get("status") or "").casefold().strip()
        if current_status not in {"validated", "report_drafted", "submitted", "resolved"}:
            raise ValueError("finding must be validated before drafting a full report")

        report_markdown = self._build_pre_audit_report_markdown(finding)
        platform = str(finding.get("platform") or "")
        template_validation = self.validate_report_template(platform=platform, report_text=report_markdown)

        submission: dict[str, Any] | None = None
        updates: dict[str, Any] = {
            "report_markdown": report_markdown,
            "status": "report_drafted",
        }

        if create_submission_draft:
            submission = self.create_submission(
                {
                    "platform": platform or "Unknown",
                    "program_name": str(finding.get("program_name") or "Unknown Program"),
                    "bug_title": str(finding.get("title") or "Untitled finding"),
                    "severity": str(finding.get("severity") or "unknown"),
                    "status": "draft",
                    "triage_notes": (
                        f"[Generated from pre-audit finding #{finding_id}]\n\n"
                        f"{report_markdown}"
                    ),
                }
            )
            updates["linked_submission_id"] = int(submission.get("id"))
            updates["status"] = "report_drafted"

        now_iso = utc_now_iso()
        updated_finding = self.db.update_pre_audit_finding(finding_id=finding_id, updates=updates, now_iso=now_iso)
        if updated_finding is None:
            raise ValueError("finding not found")

        self.db.insert_event(
            event_type="pre_audit_report_generated",
            title=f"Pre-audit report generated for finding #{finding_id}",
            details={
                "finding_id": finding_id,
                "linked_submission_id": updated_finding.get("linked_submission_id"),
                "created_submission_draft": bool(create_submission_draft),
                "actor": actor_username,
            },
            created_at=now_iso,
            program_external_id=updated_finding.get("program_external_id"),
            notified=False,
        )

        return {
            "finding": updated_finding,
            "report_markdown": report_markdown,
            "template_validation": template_validation,
            "submission": submission,
        }

    def run_pre_audit_heuristics(
        self,
        *,
        source_code: str,
        language: str = "solidity",
        max_findings: int = 120,
    ) -> dict[str, Any]:
        code = str(source_code or "")
        if not code.strip():
            raise ValueError("source_code is required")

        language_clean = str(language or "solidity").casefold().strip()
        if language_clean not in {"solidity", "sol"}:
            return {
                "language": language_clean,
                "finding_count": 0,
                "findings": [],
                "note": "Heuristics currently support Solidity only.",
            }

        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        lines = code.splitlines()
        max_items = max(1, min(1000, int(max_findings)))

        for rule in SOLIDITY_HEURISTIC_RULES:
            pattern = re.compile(str(rule.get("pattern") or ""))
            for line_no, line in enumerate(lines, start=1):
                if len(findings) >= max_items:
                    break
                if not pattern.search(line):
                    continue
                key = (str(rule.get("id") or ""), line_no)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    {
                        "heuristic_id": rule.get("id"),
                        "title": rule.get("title"),
                        "severity": rule.get("severity"),
                        "category": rule.get("category"),
                        "line": line_no,
                        "snippet": line.strip()[:220],
                        "description": rule.get("description"),
                        "recommendation": rule.get("recommendation"),
                        "ai_confidence": rule.get("confidence"),
                    }
                )
            if len(findings) >= max_items:
                break

        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda item: (rank.get(str(item.get("severity") or "").casefold(), 9), int(item.get("line") or 0)))
        return {
            "language": "solidity",
            "line_count": len(lines),
            "finding_count": len(findings),
            "findings": findings,
        }

    def set_submission_deadline(
        self,
        *,
        submission_id: int,
        due_at: str | None,
        sla_hours: int | None = None,
        remind_before_minutes: int = 60,
        active: bool = True,
    ) -> dict[str, Any]:
        submission = self.db.get_submission(submission_id)
        if submission is None:
            raise ValueError("submission not found")

        resolved_due_at = due_at
        if not resolved_due_at:
            reference = self._parse_utc_iso(str(submission.get("submitted_at") or "")) or self._parse_utc_iso(
                str(submission.get("created_at") or "")
            )
            if reference is None:
                reference = datetime.now(timezone.utc)
            resolved_due_at = (reference + timedelta(hours=max(1, int(sla_hours or 24)))).replace(microsecond=0).isoformat()

        payload = {
            "submission_id": submission_id,
            "due_at": resolved_due_at,
            "sla_hours": sla_hours,
            "remind_before_minutes": max(1, int(remind_before_minutes)),
            "active": bool(active),
        }
        return self.db.upsert_submission_deadline(payload, now_iso=utc_now_iso())

    def list_submission_deadlines(self, active_only: bool = True, limit: int = 500) -> list[dict[str, Any]]:
        rows = self.db.list_submission_deadlines(active_only=active_only, limit=max(1, limit))
        by_submission = {
            int(item.get("id")): item for item in self.db.list_submissions(limit=10000)
        }
        for row in rows:
            submission = by_submission.get(int(row.get("submission_id") or 0))
            if submission:
                row["submission"] = submission
        return rows

    def run_sla_reminders(self, trigger: str = "scheduler") -> dict[str, Any]:
        started_at = utc_now_iso()
        now_dt = self._parse_utc_iso(started_at) or datetime.now(timezone.utc)
        rows = self.list_submission_deadlines(active_only=True, limit=5000)
        sent = 0
        due_soon = 0
        overdue = 0
        for row in rows:
            due_dt = self._parse_utc_iso(str(row.get("due_at") or ""))
            if due_dt is None:
                continue
            remind_before = int(row.get("remind_before_minutes") or 60)
            last_reminder = self._parse_utc_iso(str(row.get("last_reminder_at") or ""))
            cooldown_ok = last_reminder is None or (now_dt - last_reminder) >= timedelta(hours=6)
            if not cooldown_ok:
                continue

            submission = row.get("submission") or {}
            delta_minutes = int((due_dt - now_dt).total_seconds() / 60)
            if 0 <= delta_minutes <= remind_before:
                due_soon += 1
                text = "\n".join(
                    [
                        "[SLA REMINDER]",
                        f"Submission #{submission.get('id')}",
                        f"Program: {submission.get('program_name')}",
                        f"Status: {submission.get('status')}",
                        f"Due at: {row.get('due_at')}",
                        f"Time left: {delta_minutes} min",
                    ]
                )
                if self._safe_send_notification(text):
                    sent += 1
                    self.db.update_submission_deadline(
                        int(row["submission_id"]),
                        {"last_reminder_at": started_at},
                        now_iso=started_at,
                    )
            elif delta_minutes < 0:
                overdue += 1
                text = "\n".join(
                    [
                        "[SLA OVERDUE]",
                        f"Submission #{submission.get('id')}",
                        f"Program: {submission.get('program_name')}",
                        f"Status: {submission.get('status')}",
                        f"Due at: {row.get('due_at')}",
                        f"Overdue by: {abs(delta_minutes)} min",
                    ]
                )
                if self._safe_send_notification(text):
                    sent += 1
                    self.db.update_submission_deadline(
                        int(row["submission_id"]),
                        {"last_reminder_at": started_at},
                        now_iso=started_at,
                    )

        summary = {
            "status": "ok",
            "trigger": trigger,
            "started_at": started_at,
            "tracked_deadlines": len(rows),
            "due_soon": due_soon,
            "overdue": overdue,
            "notifications": sent,
        }
        self._set_last_status("last_sla_run", summary)
        return summary

    def add_submission_evidence(
        self,
        *,
        submission_id: int,
        title: str,
        file_path: str | None = None,
        file_type: str | None = None,
        tx_hash: str | None = None,
        external_url: str | None = None,
        notes: str | None = None,
        created_by: str | None = None,
    ) -> dict[str, Any]:
        if self.db.get_submission(submission_id) is None:
            raise ValueError("submission not found")
        payload = {
            "submission_id": submission_id,
            "title": title.strip(),
            "file_path": file_path,
            "file_type": file_type,
            "tx_hash": tx_hash,
            "external_url": external_url,
            "notes": notes,
            "created_by": created_by,
        }
        return self.db.create_submission_evidence(payload, now_iso=utc_now_iso())

    def list_submission_evidence(self, submission_id: int, limit: int = 200) -> list[dict[str, Any]]:
        return self.db.list_submission_evidence(submission_id, limit=max(1, limit))

    def delete_submission_evidence(self, evidence_id: int) -> bool:
        evidence = self.db.delete_submission_evidence(evidence_id)
        if evidence is None:
            return False
        file_path = str(evidence.get("file_path") or "")
        if file_path:
            path = Path(file_path)
            if path.exists() and path.is_file():
                try:
                    path.unlink()
                except Exception:
                    logger.exception("failed to delete evidence file: %s", file_path)
        return True

    def get_submission_workflow(self, submission_id: int) -> dict[str, Any]:
        submission = self.db.get_submission(submission_id)
        if submission is None:
            raise ValueError("submission not found")
        workflow = self.db.ensure_submission_workflow(submission_id, now_iso=utc_now_iso())
        notes = self.db.list_submission_notes(submission_id, limit=200)
        return {
            "submission": submission,
            "workflow": workflow,
            "notes": notes,
        }

    def assign_submission(self, submission_id: int, user_id: int | None) -> dict[str, Any]:
        if self.db.get_submission(submission_id) is None:
            raise ValueError("submission not found")
        now_iso = utc_now_iso()
        self.db.ensure_submission_workflow(submission_id, now_iso=now_iso)
        updated = self.db.update_submission_workflow(
            submission_id=submission_id,
            updates={"assigned_user_id": user_id, "last_transition_at": now_iso},
            now_iso=now_iso,
        )
        return updated or {}

    def transition_submission(self, submission_id: int, new_stage: str) -> dict[str, Any]:
        new_stage_clean = str(new_stage or "").casefold().strip()
        if not new_stage_clean:
            raise ValueError("new stage is required")
        now_iso = utc_now_iso()
        workflow = self.db.ensure_submission_workflow(submission_id, now_iso=now_iso)
        current = str(workflow.get("stage") or "").casefold().strip() or "submitted"
        allowed = WORKFLOW_TRANSITIONS.get(current, set())
        if new_stage_clean not in allowed and current != new_stage_clean:
            raise ValueError(f"invalid transition from {current} to {new_stage_clean}")
        updated = self.db.update_submission_workflow(
            submission_id=submission_id,
            updates={"stage": new_stage_clean, "last_transition_at": now_iso},
            now_iso=now_iso,
        )
        self.db.update_submission(
            submission_id,
            updates={"status": new_stage_clean},
            now_iso=now_iso,
        )
        return updated or {}

    def set_submission_review_state(
        self,
        submission_id: int,
        *,
        approved: bool,
        reviewer_user_id: int | None,
    ) -> dict[str, Any]:
        now_iso = utc_now_iso()
        self.db.ensure_submission_workflow(submission_id, now_iso=now_iso)
        review_state = "approved" if approved else "changes_requested"
        updated = self.db.update_submission_workflow(
            submission_id=submission_id,
            updates={
                "review_state": review_state,
                "reviewer_user_id": reviewer_user_id,
                "last_transition_at": now_iso,
            },
            now_iso=now_iso,
        )
        return updated or {}

    def add_submission_note(
        self,
        submission_id: int,
        *,
        note: str,
        author_user_id: int | None = None,
        visibility: str = "internal",
    ) -> dict[str, Any]:
        if self.db.get_submission(submission_id) is None:
            raise ValueError("submission not found")
        if not note.strip():
            raise ValueError("note cannot be empty")
        payload = {
            "submission_id": submission_id,
            "author_user_id": author_user_id,
            "visibility": visibility,
            "note": note.strip(),
        }
        return self.db.create_submission_note(payload, now_iso=utc_now_iso())

    def list_submission_notes(self, submission_id: int, limit: int = 200) -> list[dict[str, Any]]:
        return self.db.list_submission_notes(submission_id, limit=max(1, limit))
