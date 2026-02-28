from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

PROGRAM_DIFF_FIELDS = (
    "name",
    "link",
    "date_launched",
    "scope_type",
    "bounty_min",
    "bounty_max",
)

SMART_CONTRACT_TERMS = (
    "smart contract",
    "smart-contract",
    "blockchain",
    "on-chain",
    "onchain",
    "web3",
    "solidity",
    "evm",
)


class Database:
    def __init__(self, database_path: Path, busy_timeout_ms: int = 5000) -> None:
        self.database_path = database_path
        self.busy_timeout_ms = max(1000, int(busy_timeout_ms))
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.database_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.initialize()

    def initialize(self) -> None:
        schema = """
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA temp_store=MEMORY;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS programs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            external_id TEXT NOT NULL,
            handle TEXT NOT NULL,
            platform TEXT NOT NULL,
            name TEXT NOT NULL,
            link TEXT,
            date_launched TEXT,
            scope_type TEXT,
            bounty_min REAL,
            bounty_max REAL,
            data_hash TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            last_changed_at TEXT NOT NULL,
            UNIQUE(source, external_id)
        );

        CREATE INDEX IF NOT EXISTS idx_programs_platform ON programs(platform);
        CREATE INDEX IF NOT EXISTS idx_programs_last_changed ON programs(last_changed_at DESC);

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            details_json TEXT NOT NULL,
            program_external_id TEXT,
            created_at TEXT NOT NULL,
            notified INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_events_type_created ON events(event_type, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_events_program_created ON events(program_external_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS github_watches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_external_id TEXT,
            repo_owner TEXT NOT NULL,
            repo_name TEXT NOT NULL,
            file_path TEXT NOT NULL DEFAULT '',
            branch TEXT NOT NULL DEFAULT 'main',
            last_sha TEXT,
            last_checked_at TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(repo_owner, repo_name, file_path, branch)
        );

        CREATE INDEX IF NOT EXISTS idx_github_watches_active ON github_watches(active, updated_at DESC);

        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform TEXT NOT NULL,
            program_name TEXT NOT NULL,
            bug_title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            submitted_at TEXT,
            triage_notes TEXT,
            rejection_reason TEXT,
            report_pdf_path TEXT,
            pdf_summary TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status, updated_at DESC);

        CREATE TABLE IF NOT EXISTS pre_audit_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_external_id TEXT,
            platform TEXT,
            program_name TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'new',
            category TEXT,
            description TEXT NOT NULL,
            impact TEXT,
            poc_steps TEXT,
            recommendation TEXT,
            source TEXT NOT NULL DEFAULT 'manual',
            source_reference TEXT,
            target_github_url TEXT,
            ai_confidence REAL,
            tags_json TEXT NOT NULL DEFAULT '[]',
            report_markdown TEXT,
            linked_submission_id INTEGER,
            created_by_user_id INTEGER,
            created_by_username TEXT,
            validated_by_user_id INTEGER,
            validated_by_username TEXT,
            validated_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_pre_audit_findings_status_updated
            ON pre_audit_findings(status, updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_pre_audit_findings_program_updated
            ON pre_audit_findings(program_external_id, updated_at DESC);

        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            min_bounty REAL,
            platforms_json TEXT NOT NULL DEFAULT '[]',
            keywords_json TEXT NOT NULL DEFAULT '[]',
            event_types_json TEXT NOT NULL DEFAULT '[]',
            digest_only INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled, updated_at DESC);

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            api_key TEXT NOT NULL UNIQUE,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_users_role_active ON users(role, active, updated_at DESC);

        CREATE TABLE IF NOT EXISTS system_state (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_type TEXT NOT NULL,
            trigger TEXT NOT NULL,
            status TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT,
            error TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_scan_jobs_status_created ON scan_jobs(status, created_at DESC);

        CREATE TABLE IF NOT EXISTS program_tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_external_id TEXT NOT NULL,
            tag TEXT NOT NULL,
            note TEXT,
            manual_boost REAL NOT NULL DEFAULT 0,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(program_external_id, tag)
        );

        CREATE INDEX IF NOT EXISTS idx_program_tags_tag ON program_tags(tag, updated_at DESC);

        CREATE TABLE IF NOT EXISTS submission_deadlines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER NOT NULL UNIQUE,
            due_at TEXT NOT NULL,
            sla_hours INTEGER,
            remind_before_minutes INTEGER NOT NULL DEFAULT 60,
            last_reminder_at TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_submission_deadlines_due ON submission_deadlines(active, due_at);

        CREATE TABLE IF NOT EXISTS submission_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            file_path TEXT,
            file_type TEXT,
            tx_hash TEXT,
            external_url TEXT,
            notes TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_submission_evidence_submission ON submission_evidence(submission_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS submission_workflow (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER NOT NULL UNIQUE,
            assigned_user_id INTEGER,
            stage TEXT NOT NULL DEFAULT 'submitted',
            review_state TEXT NOT NULL DEFAULT 'pending',
            reviewer_user_id INTEGER,
            last_transition_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_submission_workflow_stage ON submission_workflow(stage, updated_at DESC);

        CREATE TABLE IF NOT EXISTS submission_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER NOT NULL,
            author_user_id INTEGER,
            visibility TEXT NOT NULL DEFAULT 'internal',
            note TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_submission_notes_submission ON submission_notes(submission_id, created_at DESC);
        """
        with self._lock:
            self._conn.executescript(schema)
            self._conn.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def count_programs(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS total FROM programs").fetchone()
        return int(row["total"]) if row else 0

    def upsert_program(
        self,
        program: dict[str, Any],
        now_iso: str,
    ) -> tuple[str, list[str], dict[str, dict[str, Any]]]:
        with self._lock:
            existing = self._conn.execute(
                """
                SELECT *
                FROM programs
                WHERE source = ? AND external_id = ?
                """,
                (program["source"], program["external_id"]),
            ).fetchone()

            if existing is None:
                self._conn.execute(
                    """
                    INSERT INTO programs (
                        source, external_id, handle, platform, name, link, date_launched,
                        scope_type, bounty_min, bounty_max, data_hash, raw_json,
                        first_seen_at, last_seen_at, last_changed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        program["source"],
                        program["external_id"],
                        program["handle"],
                        program["platform"],
                        program["name"],
                        program.get("link"),
                        program.get("date_launched"),
                        program.get("scope_type"),
                        program.get("bounty_min"),
                        program.get("bounty_max"),
                        program["data_hash"],
                        json.dumps(program["raw_json"], sort_keys=True),
                        now_iso,
                        now_iso,
                        now_iso,
                    ),
                )
                self._conn.commit()
                return "created", [], {}

            if existing["data_hash"] == program["data_hash"]:
                self._conn.execute(
                    """
                    UPDATE programs
                    SET last_seen_at = ?
                    WHERE id = ?
                    """,
                    (now_iso, existing["id"]),
                )
                self._conn.commit()
                return "unchanged", [], {}

            old_json = json.loads(existing["raw_json"])
            changed_fields, field_diffs = self._diff_program_fields(old_json, program["raw_json"])

            self._conn.execute(
                """
                UPDATE programs
                SET name = ?,
                    link = ?,
                    date_launched = ?,
                    scope_type = ?,
                    bounty_min = ?,
                    bounty_max = ?,
                    data_hash = ?,
                    raw_json = ?,
                    last_seen_at = ?,
                    last_changed_at = ?
                WHERE id = ?
                """,
                (
                    program["name"],
                    program.get("link"),
                    program.get("date_launched"),
                    program.get("scope_type"),
                    program.get("bounty_min"),
                    program.get("bounty_max"),
                    program["data_hash"],
                    json.dumps(program["raw_json"], sort_keys=True),
                    now_iso,
                    now_iso,
                    existing["id"],
                ),
            )
            self._conn.commit()
            return "updated", changed_fields, field_diffs

    @staticmethod
    def _diff_program_fields(
        old_json: dict[str, Any],
        new_json: dict[str, Any],
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        changed: list[str] = []
        details: dict[str, dict[str, Any]] = {}
        for field in PROGRAM_DIFF_FIELDS:
            old_value = old_json.get(field)
            new_value = new_json.get(field)
            if old_value != new_value:
                changed.append(field)
                details[field] = {
                    "old": old_value,
                    "new": new_value,
                }
        return changed, details

    def get_program(self, external_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM programs WHERE external_id = ?",
                (external_id,),
            ).fetchone()
        if row is None:
            return None
        return self._program_row_to_dict(row)

    def list_programs(
        self,
        limit: int = 100,
        platform: str | None = None,
        updated_only: bool = False,
        focus: str = "all",
        q: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM programs"
        params: list[Any] = []
        filters: list[str] = []

        if platform:
            filters.append("LOWER(platform) = LOWER(?)")
            params.append(platform)

        if updated_only:
            filters.append("last_changed_at > first_seen_at")

        if q and q.strip():
            filters.append(
                "("
                "LOWER(name) LIKE LOWER(?) OR "
                "LOWER(handle) LIKE LOWER(?) OR "
                "LOWER(external_id) LIKE LOWER(?) OR "
                "LOWER(COALESCE(link, '')) LIKE LOWER(?)"
                ")"
            )
            like_q = f"%{q.strip()}%"
            params.extend([like_q, like_q, like_q, like_q])

        if filters:
            query += " WHERE " + " AND ".join(filters)

        query += " ORDER BY last_changed_at DESC"

        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()

        programs = [self._program_row_to_dict(row) for row in rows]

        if focus == "smart_contract":
            programs = [item for item in programs if self._matches_smart_contract_focus(item)]

        return programs[: max(1, limit)]

    def insert_event(
        self,
        *,
        event_type: str,
        title: str,
        details: dict[str, Any],
        created_at: str,
        program_external_id: str | None = None,
        notified: bool = False,
    ) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO events (event_type, title, details_json, program_external_id, created_at, notified)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event_type,
                    title,
                    json.dumps(details, sort_keys=True),
                    program_external_id,
                    created_at,
                    1 if notified else 0,
                ),
            )
            self._conn.commit()
            return int(cursor.lastrowid)

    def mark_event_notified(self, event_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE events SET notified = 1 WHERE id = ?",
                (event_id,),
            )
            self._conn.commit()

    def list_events(self, limit: int = 100, event_type: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM events"
        params: list[Any] = []

        if event_type:
            query += " WHERE event_type = ?"
            params.append(event_type)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()

        events: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            events.append(item)
        return events

    def list_program_events(self, external_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM events
                WHERE program_external_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (external_id, max(1, limit)),
            ).fetchall()

        events: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            events.append(item)
        return events

    def list_program_submissions(self, program_name: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM submissions
                WHERE LOWER(program_name) = LOWER(?)
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (program_name, max(1, limit)),
            ).fetchall()
        return [dict(row) for row in rows]

    def create_alert_rule(self, payload: dict[str, Any], now_iso: str) -> dict[str, Any]:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO alert_rules (
                    name, enabled, min_bounty, platforms_json, keywords_json,
                    event_types_json, digest_only, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["name"],
                    1 if payload.get("enabled", True) else 0,
                    payload.get("min_bounty"),
                    json.dumps(payload.get("platforms", []), sort_keys=True),
                    json.dumps(payload.get("keywords", []), sort_keys=True),
                    json.dumps(payload.get("event_types", []), sort_keys=True),
                    1 if payload.get("digest_only", False) else 0,
                    now_iso,
                    now_iso,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM alert_rules WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
        if row is None:
            raise RuntimeError("failed to create alert rule")
        return self._alert_rule_row_to_dict(row)

    def list_alert_rules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM alert_rules"
        params: list[Any] = []
        if enabled_only:
            query += " WHERE enabled = 1"
        query += " ORDER BY updated_at DESC"
        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [self._alert_rule_row_to_dict(row) for row in rows]

    def update_alert_rule(self, rule_id: int, updates: dict[str, Any], now_iso: str) -> dict[str, Any] | None:
        allowed_fields = {
            "name",
            "enabled",
            "min_bounty",
            "platforms",
            "keywords",
            "event_types",
            "digest_only",
        }
        filtered = {k: v for k, v in updates.items() if k in allowed_fields}
        if not filtered:
            with self._lock:
                row = self._conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
            return self._alert_rule_row_to_dict(row) if row else None

        assignments: list[str] = []
        values: list[Any] = []
        for key, value in filtered.items():
            if key in {"platforms", "keywords", "event_types"}:
                assignments.append(f"{key}_json = ?")
                values.append(json.dumps(value or [], sort_keys=True))
            elif key in {"enabled", "digest_only"}:
                assignments.append(f"{key} = ?")
                values.append(1 if value else 0)
            else:
                assignments.append(f"{key} = ?")
                values.append(value)
        assignments.append("updated_at = ?")
        values.append(now_iso)
        values.append(rule_id)

        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE alert_rules SET {', '.join(assignments)} WHERE id = ?",
                tuple(values),
            )
            self._conn.commit()
            if cursor.rowcount == 0:
                return None
            row = self._conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
        return self._alert_rule_row_to_dict(row) if row else None

    def delete_alert_rule(self, rule_id: int) -> bool:
        with self._lock:
            cursor = self._conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
            self._conn.commit()
            return cursor.rowcount > 0

    def create_user(self, payload: dict[str, Any], now_iso: str) -> dict[str, Any]:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO users (username, role, api_key, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["username"],
                    payload["role"],
                    payload["api_key"],
                    1 if payload.get("active", True) else 0,
                    now_iso,
                    now_iso,
                ),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
        if row is None:
            raise RuntimeError("failed to create user")
        return dict(row)

    def list_users(self, active_only: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM users"
        params: list[Any] = []
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY updated_at DESC"
        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def get_user_by_api_key(self, api_key: str) -> dict[str, Any] | None:
        if not api_key:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE api_key = ? AND active = 1",
                (api_key,),
            ).fetchone()
        return dict(row) if row else None

    def update_user(self, user_id: int, updates: dict[str, Any], now_iso: str) -> dict[str, Any] | None:
        allowed_fields = {"username", "role", "api_key", "active"}
        filtered = {k: v for k, v in updates.items() if k in allowed_fields}
        if not filtered:
            with self._lock:
                row = self._conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(row) if row else None

        assignments: list[str] = []
        values: list[Any] = []
        for key, value in filtered.items():
            if key == "active":
                assignments.append("active = ?")
                values.append(1 if value else 0)
            else:
                assignments.append(f"{key} = ?")
                values.append(value)
        assignments.append("updated_at = ?")
        values.append(now_iso)
        values.append(user_id)

        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE users SET {', '.join(assignments)} WHERE id = ?",
                tuple(values),
            )
            self._conn.commit()
            if cursor.rowcount == 0:
                return None
            row = self._conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def delete_user(self, user_id: int) -> bool:
        with self._lock:
            cursor = self._conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            self._conn.commit()
            return cursor.rowcount > 0

    def get_state(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value_json FROM system_state WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(str(row["value_json"]))
        except json.JSONDecodeError:
            return None

    def set_state(self, key: str, value: dict[str, Any], now_iso: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO system_state (key, value_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                (
                    key,
                    json.dumps(value, sort_keys=True),
                    now_iso,
                ),
            )
            self._conn.commit()

    def create_scan_job(
        self,
        *,
        job_type: str,
        trigger: str,
        payload: dict[str, Any],
        now_iso: str,
    ) -> dict[str, Any]:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO scan_jobs (job_type, trigger, status, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    job_type,
                    trigger,
                    "queued",
                    json.dumps(payload or {}, sort_keys=True),
                    now_iso,
                ),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (cursor.lastrowid,)).fetchone()
        if row is None:
            raise RuntimeError("failed to create scan job")
        return self._scan_job_row_to_dict(row)

    def update_scan_job(
        self,
        job_id: int,
        *,
        status: str | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any] | None:
        assignments: list[str] = []
        values: list[Any] = []
        if status is not None:
            assignments.append("status = ?")
            values.append(status)
        if started_at is not None:
            assignments.append("started_at = ?")
            values.append(started_at)
        if finished_at is not None:
            assignments.append("finished_at = ?")
            values.append(finished_at)
        if result is not None:
            assignments.append("result_json = ?")
            values.append(json.dumps(result, sort_keys=True))
        if error is not None:
            assignments.append("error = ?")
            values.append(error)
        if not assignments:
            return self.get_scan_job(job_id)

        values.append(job_id)
        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE scan_jobs SET {', '.join(assignments)} WHERE id = ?",
                tuple(values),
            )
            self._conn.commit()
            if cursor.rowcount == 0:
                return None
            row = self._conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        return self._scan_job_row_to_dict(row) if row else None

    def get_scan_job(self, job_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        return self._scan_job_row_to_dict(row) if row else None

    def list_scan_jobs(self, limit: int = 100, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM scan_jobs"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, limit))
        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [self._scan_job_row_to_dict(row) for row in rows]

    def mark_stale_scan_jobs(self, *, stale_before_iso: str, now_iso: str) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'error',
                    error = 'job marked stale after restart',
                    finished_at = COALESCE(finished_at, ?)
                WHERE status IN ('queued', 'running')
                  AND created_at < ?
                """,
                (now_iso, stale_before_iso),
            )
            self._conn.commit()
            return int(cursor.rowcount)

    def prune_events(self, *, older_than_iso: str) -> int:
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM events WHERE created_at < ?",
                (older_than_iso,),
            )
            self._conn.commit()
            return int(cursor.rowcount)

    def prune_scan_jobs(self, *, older_than_iso: str) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                DELETE FROM scan_jobs
                WHERE created_at < ?
                  AND status IN ('done', 'error')
                """,
                (older_than_iso,),
            )
            self._conn.commit()
            return int(cursor.rowcount)

    def upsert_program_tag(self, payload: dict[str, Any], now_iso: str) -> dict[str, Any]:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO program_tags (
                    program_external_id, tag, note, manual_boost, created_by, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(program_external_id, tag) DO UPDATE SET
                    note = excluded.note,
                    manual_boost = excluded.manual_boost,
                    created_by = excluded.created_by,
                    updated_at = excluded.updated_at
                """,
                (
                    payload["program_external_id"],
                    payload["tag"],
                    payload.get("note"),
                    payload.get("manual_boost", 0),
                    payload.get("created_by"),
                    now_iso,
                    now_iso,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                """
                SELECT * FROM program_tags
                WHERE program_external_id = ? AND tag = ?
                """,
                (payload["program_external_id"], payload["tag"]),
            ).fetchone()
        if row is None:
            raise RuntimeError("failed to upsert program tag")
        return dict(row)

    def list_program_tags(
        self,
        *,
        program_external_id: str | None = None,
        tag: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM program_tags"
        params: list[Any] = []
        filters: list[str] = []
        if program_external_id:
            filters.append("program_external_id = ?")
            params.append(program_external_id)
        if tag:
            filters.append("LOWER(tag) = LOWER(?)")
            params.append(tag)
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY updated_at DESC"
        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def delete_program_tag(self, tag_id: int) -> bool:
        with self._lock:
            cursor = self._conn.execute("DELETE FROM program_tags WHERE id = ?", (tag_id,))
            self._conn.commit()
            return cursor.rowcount > 0

    def upsert_submission_deadline(self, payload: dict[str, Any], now_iso: str) -> dict[str, Any]:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO submission_deadlines (
                    submission_id, due_at, sla_hours, remind_before_minutes,
                    last_reminder_at, active, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(submission_id) DO UPDATE SET
                    due_at = excluded.due_at,
                    sla_hours = excluded.sla_hours,
                    remind_before_minutes = excluded.remind_before_minutes,
                    active = excluded.active,
                    updated_at = excluded.updated_at
                """,
                (
                    payload["submission_id"],
                    payload["due_at"],
                    payload.get("sla_hours"),
                    payload.get("remind_before_minutes", 60),
                    payload.get("last_reminder_at"),
                    1 if payload.get("active", True) else 0,
                    now_iso,
                    now_iso,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM submission_deadlines WHERE submission_id = ?",
                (payload["submission_id"],),
            ).fetchone()
        return dict(row) if row else {}

    def get_submission_deadline(self, submission_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM submission_deadlines WHERE submission_id = ?",
                (submission_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_submission_deadlines(
        self,
        *,
        active_only: bool = True,
        due_before: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM submission_deadlines"
        params: list[Any] = []
        filters: list[str] = []
        if active_only:
            filters.append("active = 1")
        if due_before:
            filters.append("due_at <= ?")
            params.append(due_before)
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY due_at ASC LIMIT ?"
        params.append(max(1, limit))
        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def update_submission_deadline(
        self,
        submission_id: int,
        updates: dict[str, Any],
        now_iso: str,
    ) -> dict[str, Any] | None:
        allowed = {
            "due_at",
            "sla_hours",
            "remind_before_minutes",
            "last_reminder_at",
            "active",
        }
        filtered = {k: v for k, v in updates.items() if k in allowed}
        if not filtered:
            return self.get_submission_deadline(submission_id)
        assignments: list[str] = []
        values: list[Any] = []
        for key, value in filtered.items():
            if key == "active":
                assignments.append("active = ?")
                values.append(1 if value else 0)
            else:
                assignments.append(f"{key} = ?")
                values.append(value)
        assignments.append("updated_at = ?")
        values.append(now_iso)
        values.append(submission_id)
        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE submission_deadlines SET {', '.join(assignments)} WHERE submission_id = ?",
                tuple(values),
            )
            self._conn.commit()
            if cursor.rowcount == 0:
                return None
            row = self._conn.execute(
                "SELECT * FROM submission_deadlines WHERE submission_id = ?",
                (submission_id,),
            ).fetchone()
        return dict(row) if row else None

    def create_submission_evidence(self, payload: dict[str, Any], now_iso: str) -> dict[str, Any]:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO submission_evidence (
                    submission_id, title, file_path, file_type, tx_hash, external_url,
                    notes, created_by, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["submission_id"],
                    payload["title"],
                    payload.get("file_path"),
                    payload.get("file_type"),
                    payload.get("tx_hash"),
                    payload.get("external_url"),
                    payload.get("notes"),
                    payload.get("created_by"),
                    now_iso,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM submission_evidence WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
        if row is None:
            raise RuntimeError("failed to create evidence")
        return dict(row)

    def list_submission_evidence(self, submission_id: int, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM submission_evidence
                WHERE submission_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (submission_id, max(1, limit)),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_submission_evidence(self, evidence_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM submission_evidence WHERE id = ?",
                (evidence_id,),
            ).fetchone()
        return dict(row) if row else None

    def delete_submission_evidence(self, evidence_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM submission_evidence WHERE id = ?",
                (evidence_id,),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute("DELETE FROM submission_evidence WHERE id = ?", (evidence_id,))
            self._conn.commit()
        return dict(row)

    def ensure_submission_workflow(self, submission_id: int, now_iso: str) -> dict[str, Any]:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO submission_workflow (
                    submission_id, stage, review_state, last_transition_at, created_at, updated_at
                )
                VALUES (?, 'submitted', 'pending', ?, ?, ?)
                ON CONFLICT(submission_id) DO NOTHING
                """,
                (submission_id, now_iso, now_iso, now_iso),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM submission_workflow WHERE submission_id = ?",
                (submission_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError("failed to ensure workflow")
        return dict(row)

    def get_submission_workflow(self, submission_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM submission_workflow WHERE submission_id = ?",
                (submission_id,),
            ).fetchone()
        return dict(row) if row else None

    def update_submission_workflow(
        self,
        submission_id: int,
        updates: dict[str, Any],
        now_iso: str,
    ) -> dict[str, Any] | None:
        allowed = {
            "assigned_user_id",
            "stage",
            "review_state",
            "reviewer_user_id",
            "last_transition_at",
        }
        filtered = {k: v for k, v in updates.items() if k in allowed}
        if not filtered:
            return self.get_submission_workflow(submission_id)
        assignments: list[str] = []
        values: list[Any] = []
        for key, value in filtered.items():
            assignments.append(f"{key} = ?")
            values.append(value)
        assignments.append("updated_at = ?")
        values.append(now_iso)
        values.append(submission_id)
        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE submission_workflow SET {', '.join(assignments)} WHERE submission_id = ?",
                tuple(values),
            )
            self._conn.commit()
            if cursor.rowcount == 0:
                return None
            row = self._conn.execute(
                "SELECT * FROM submission_workflow WHERE submission_id = ?",
                (submission_id,),
            ).fetchone()
        return dict(row) if row else None

    def create_submission_note(self, payload: dict[str, Any], now_iso: str) -> dict[str, Any]:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO submission_notes (submission_id, author_user_id, visibility, note, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    payload["submission_id"],
                    payload.get("author_user_id"),
                    payload.get("visibility", "internal"),
                    payload["note"],
                    now_iso,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM submission_notes WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
        if row is None:
            raise RuntimeError("failed to create note")
        return dict(row)

    def list_submission_notes(self, submission_id: int, limit: int = 300) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM submission_notes
                WHERE submission_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (submission_id, max(1, limit)),
            ).fetchall()
        return [dict(row) for row in rows]

    def add_github_watch(
        self,
        *,
        program_external_id: str | None,
        repo_owner: str,
        repo_name: str,
        file_path: str,
        branch: str,
        metadata: dict[str, Any],
        now_iso: str,
    ) -> dict[str, Any]:
        file_path = file_path.strip("/")

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO github_watches (
                    program_external_id, repo_owner, repo_name, file_path, branch,
                    metadata_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repo_owner, repo_name, file_path, branch)
                DO UPDATE SET
                    active = 1,
                    program_external_id = COALESCE(excluded.program_external_id, github_watches.program_external_id),
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (
                    program_external_id,
                    repo_owner,
                    repo_name,
                    file_path,
                    branch,
                    json.dumps(metadata, sort_keys=True),
                    now_iso,
                    now_iso,
                ),
            )
            self._conn.commit()

            row = self._conn.execute(
                """
                SELECT * FROM github_watches
                WHERE repo_owner = ? AND repo_name = ? AND file_path = ? AND branch = ?
                """,
                (repo_owner, repo_name, file_path, branch),
            ).fetchone()

        if row is None:
            raise RuntimeError("failed to create github watch")
        return self._watch_row_to_dict(row)

    def list_github_watches(
        self,
        active_only: bool = True,
        q: str | None = None,
        program_name: str | None = None,
    ) -> list[dict[str, Any]]:
        query = (
            "SELECT gw.*, p.program_name "
            "FROM github_watches gw "
            "LEFT JOIN ("
            "  SELECT external_id, MAX(name) AS program_name "
            "  FROM programs GROUP BY external_id"
            ") p ON p.external_id = gw.program_external_id"
        )
        params: list[Any] = []
        filters: list[str] = []

        if active_only:
            filters.append("gw.active = 1")

        if q and q.strip():
            like_q = f"%{q.strip()}%"
            filters.append(
                "("
                "LOWER(gw.repo_owner) LIKE LOWER(?) OR "
                "LOWER(gw.repo_name) LIKE LOWER(?) OR "
                "LOWER(gw.file_path) LIKE LOWER(?) OR "
                "LOWER(gw.branch) LIKE LOWER(?) OR "
                "LOWER(COALESCE(gw.program_external_id, '')) LIKE LOWER(?) OR "
                "LOWER(COALESCE(p.program_name, '')) LIKE LOWER(?)"
                ")"
            )
            params.extend([like_q, like_q, like_q, like_q, like_q, like_q])

        if program_name and program_name.strip():
            params.append(f"%{program_name.strip()}%")
            filters.append("LOWER(COALESCE(p.program_name, '')) LIKE LOWER(?)")

        if filters:
            query += " WHERE " + " AND ".join(filters)

        query += " ORDER BY gw.updated_at DESC"

        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()

        return [self._watch_row_to_dict(row) for row in rows]

    def list_program_watches(self, external_id: str, active_only: bool = True) -> list[dict[str, Any]]:
        query = (
            "SELECT gw.*, p.program_name "
            "FROM github_watches gw "
            "LEFT JOIN ("
            "  SELECT external_id, MAX(name) AS program_name "
            "  FROM programs GROUP BY external_id"
            ") p ON p.external_id = gw.program_external_id "
            "WHERE gw.program_external_id = ?"
        )
        params: list[Any] = [external_id]
        if active_only:
            query += " AND gw.active = 1"
        query += " ORDER BY gw.updated_at DESC"
        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [self._watch_row_to_dict(row) for row in rows]

    def deactivate_github_watch(self, watch_id: int, now_iso: str) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE github_watches
                SET active = 0, updated_at = ?
                WHERE id = ?
                """,
                (now_iso, watch_id),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def update_github_watch_state(self, watch_id: int, last_sha: str, now_iso: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE github_watches
                SET last_sha = ?, last_checked_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (last_sha, now_iso, now_iso, watch_id),
            )
            self._conn.commit()

    def create_submission(self, payload: dict[str, Any], now_iso: str) -> dict[str, Any]:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO submissions (
                    platform, program_name, bug_title, severity, status,
                    submitted_at, triage_notes, rejection_reason,
                    report_pdf_path, pdf_summary, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["platform"],
                    payload["program_name"],
                    payload["bug_title"],
                    payload["severity"],
                    payload["status"],
                    payload.get("submitted_at"),
                    payload.get("triage_notes"),
                    payload.get("rejection_reason"),
                    payload.get("report_pdf_path"),
                    payload.get("pdf_summary"),
                    now_iso,
                    now_iso,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM submissions WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()

        if row is None:
            raise RuntimeError("failed to create submission")
        return dict(row)

    def get_submission(self, submission_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM submissions WHERE id = ?",
                (submission_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_submissions(self, limit: int = 100, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM submissions"
        params: list[Any] = []

        if status:
            query += " WHERE status = ?"
            params.append(status)

        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()

        return [dict(row) for row in rows]

    def update_submission(self, submission_id: int, updates: dict[str, Any], now_iso: str) -> dict[str, Any] | None:
        allowed_fields = {
            "platform",
            "program_name",
            "bug_title",
            "severity",
            "status",
            "submitted_at",
            "triage_notes",
            "rejection_reason",
            "report_pdf_path",
            "pdf_summary",
        }
        filtered = {key: value for key, value in updates.items() if key in allowed_fields}

        if not filtered:
            with self._lock:
                row = self._conn.execute(
                    "SELECT * FROM submissions WHERE id = ?",
                    (submission_id,),
                ).fetchone()
            return dict(row) if row else None

        assignments = ", ".join(f"{key} = ?" for key in filtered)
        values = list(filtered.values()) + [now_iso, submission_id]

        with self._lock:
            cursor = self._conn.execute(
                f"""
                UPDATE submissions
                SET {assignments}, updated_at = ?
                WHERE id = ?
                """,
                tuple(values),
            )
            self._conn.commit()

            if cursor.rowcount == 0:
                return None

            row = self._conn.execute(
                "SELECT * FROM submissions WHERE id = ?",
                (submission_id,),
            ).fetchone()

        return dict(row) if row else None

    def create_pre_audit_finding(self, payload: dict[str, Any], now_iso: str) -> dict[str, Any]:
        tags = payload.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO pre_audit_findings (
                    program_external_id, platform, program_name, title, severity, status, category,
                    description, impact, poc_steps, recommendation, source, source_reference,
                    target_github_url, ai_confidence, tags_json, report_markdown, linked_submission_id,
                    created_by_user_id, created_by_username, validated_by_user_id, validated_by_username,
                    validated_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.get("program_external_id"),
                    payload.get("platform"),
                    payload.get("program_name"),
                    payload["title"],
                    payload.get("severity", "medium"),
                    payload.get("status", "new"),
                    payload.get("category"),
                    payload["description"],
                    payload.get("impact"),
                    payload.get("poc_steps"),
                    payload.get("recommendation"),
                    payload.get("source", "manual"),
                    payload.get("source_reference"),
                    payload.get("target_github_url"),
                    payload.get("ai_confidence"),
                    json.dumps(tags, sort_keys=True),
                    payload.get("report_markdown"),
                    payload.get("linked_submission_id"),
                    payload.get("created_by_user_id"),
                    payload.get("created_by_username"),
                    payload.get("validated_by_user_id"),
                    payload.get("validated_by_username"),
                    payload.get("validated_at"),
                    now_iso,
                    now_iso,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM pre_audit_findings WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
        if row is None:
            raise RuntimeError("failed to create pre-audit finding")
        return self._pre_audit_row_to_dict(row)

    def get_pre_audit_finding(self, finding_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM pre_audit_findings WHERE id = ?",
                (finding_id,),
            ).fetchone()
        return self._pre_audit_row_to_dict(row) if row else None

    def list_pre_audit_findings(
        self,
        *,
        limit: int = 200,
        status: str | None = None,
        platform: str | None = None,
        program_external_id: str | None = None,
        q: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM pre_audit_findings"
        params: list[Any] = []
        filters: list[str] = []

        if status and status.strip():
            filters.append("LOWER(status) = LOWER(?)")
            params.append(status.strip())

        if platform and platform.strip():
            filters.append("LOWER(COALESCE(platform, '')) = LOWER(?)")
            params.append(platform.strip())

        if program_external_id and program_external_id.strip():
            filters.append("program_external_id = ?")
            params.append(program_external_id.strip())

        if q and q.strip():
            like_q = f"%{q.strip()}%"
            filters.append(
                "("
                "LOWER(title) LIKE LOWER(?) OR "
                "LOWER(description) LIKE LOWER(?) OR "
                "LOWER(COALESCE(program_name, '')) LIKE LOWER(?) OR "
                "LOWER(COALESCE(platform, '')) LIKE LOWER(?) OR "
                "LOWER(COALESCE(category, '')) LIKE LOWER(?)"
                ")"
            )
            params.extend([like_q, like_q, like_q, like_q, like_q])

        if filters:
            query += " WHERE " + " AND ".join(filters)

        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, limit))

        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()

        return [self._pre_audit_row_to_dict(row) for row in rows]

    def update_pre_audit_finding(
        self,
        finding_id: int,
        updates: dict[str, Any],
        now_iso: str,
    ) -> dict[str, Any] | None:
        allowed_fields = {
            "program_external_id",
            "platform",
            "program_name",
            "title",
            "severity",
            "status",
            "category",
            "description",
            "impact",
            "poc_steps",
            "recommendation",
            "source",
            "source_reference",
            "target_github_url",
            "ai_confidence",
            "tags",
            "report_markdown",
            "linked_submission_id",
            "validated_by_user_id",
            "validated_by_username",
            "validated_at",
        }
        filtered = {key: value for key, value in updates.items() if key in allowed_fields}
        if not filtered:
            return self.get_pre_audit_finding(finding_id)

        assignments: list[str] = []
        values: list[Any] = []
        for key, value in filtered.items():
            if key == "tags":
                tags = value if isinstance(value, list) else []
                assignments.append("tags_json = ?")
                values.append(json.dumps(tags, sort_keys=True))
            else:
                assignments.append(f"{key} = ?")
                values.append(value)
        assignments.append("updated_at = ?")
        values.append(now_iso)
        values.append(finding_id)

        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE pre_audit_findings SET {', '.join(assignments)} WHERE id = ?",
                tuple(values),
            )
            self._conn.commit()
            if cursor.rowcount == 0:
                return None
            row = self._conn.execute(
                "SELECT * FROM pre_audit_findings WHERE id = ?",
                (finding_id,),
            ).fetchone()
        return self._pre_audit_row_to_dict(row) if row else None

    @staticmethod
    def _program_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["raw"] = json.loads(item.pop("raw_json"))
        return item

    @staticmethod
    def _matches_smart_contract_focus(item: dict[str, Any]) -> bool:
        raw = item.get("raw") or {}
        scope_tags = raw.get("scope_tags") if isinstance(raw, dict) else []
        if not isinstance(scope_tags, list):
            scope_tags = []

        parts = [
            str(item.get("name") or ""),
            str(item.get("scope_type") or ""),
            str(item.get("platform") or ""),
            " ".join(str(tag) for tag in scope_tags),
        ]
        blob = " ".join(parts).casefold()
        return any(term in blob for term in SMART_CONTRACT_TERMS)

    @staticmethod
    def _watch_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["metadata"] = json.loads(item.pop("metadata_json"))
        owner = str(item.get("repo_owner") or "").strip()
        repo = str(item.get("repo_name") or "").strip()
        branch = str(item.get("branch") or "main").strip() or "main"
        file_path = str(item.get("file_path") or "").strip("/")
        base = f"https://github.com/{owner}/{repo}"
        if file_path:
            item["github_url"] = f"{base}/tree/{branch}/{file_path}"
        else:
            item["github_url"] = f"{base}/tree/{branch}"
        return item

    @staticmethod
    def _scan_job_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        for key in ("payload_json", "result_json"):
            raw = item.pop(key, None)
            if raw is None:
                parsed = None
            else:
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    parsed = None
            item[key.replace("_json", "")] = parsed
        return item

    @staticmethod
    def _alert_rule_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        for key in ("platforms_json", "keywords_json", "event_types_json"):
            raw = item.pop(key, "[]")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = []
            item[key.replace("_json", "")] = parsed if isinstance(parsed, list) else []
        item["enabled"] = 1 if item.get("enabled") else 0
        item["digest_only"] = 1 if item.get("digest_only") else 0
        return item

    @staticmethod
    def _pre_audit_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        raw_tags = item.pop("tags_json", "[]")
        try:
            tags = json.loads(raw_tags)
        except json.JSONDecodeError:
            tags = []
        item["tags"] = tags if isinstance(tags, list) else []
        return item
