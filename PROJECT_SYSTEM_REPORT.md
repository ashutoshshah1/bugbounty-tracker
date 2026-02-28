# Bug Bounty Program Tracker
## Project and System Report

Generated on: 2026-02-28 11:00:21 EST (2026-02-28 16:00:21 UTC)

### 1. Project Identity

- Project name: `Bug Bounty Program Tracker`
- Primary goal: Track bug bounty programs, detect updates, monitor GitHub scope targets, and support submission workflow.
- Application style: FastAPI backend + scheduler + SQLite + web dashboard.
- Source layout:
  - Backend: `app/`
  - Frontend: `web/`
  - Operations: `ops/`
  - Data: `data/`

### 2. Host System Snapshot

- Host OS: `Kali GNU/Linux Rolling`
- Kernel: `Linux kali 6.18.9+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.18.9-1kali1 (2026-02-10) x86_64 GNU/Linux`
- Python runtime: `3.13.11`
- Current project path: `/home/bratwork/Desktop/live`
- App timezone setting: `UTC`

### 3. Runtime Configuration Snapshot (Sanitized)

- Data directory: `/home/bratwork/Desktop/live/data`
- SQLite database: `/home/bratwork/Desktop/live/data/tracker.db`
- Reports directory: `/home/bratwork/Desktop/live/data/reports`
- Scan intervals:
  - `BBRADAR_INTERVAL_MINUTES=30`
  - `GITHUB_INTERVAL_MINUTES=60`
  - `DIGEST_INTERVAL_HOURS=24` (`enabled=true`)
  - `BACKUP_INTERVAL_HOURS=24` (`enabled=true`)
  - `SLA_REMINDER_INTERVAL_MINUTES=30` (`enabled=true`)
  - `HOUSEKEEPING_INTERVAL_HOURS=6` (`enabled=true`)
- Queue and retention:
  - `JOB_WORKER_COUNT=4`
  - `STALE_JOB_TIMEOUT_MINUTES=120`
  - `EVENT_RETENTION_DAYS=120`
  - `JOB_RETENTION_DAYS=30`
- Tracking scope:
  - Platforms: `Sherlock, Immunefi, Code4rena, HackenProof`
- Integration readiness:
  - Telegram configured: `true`
  - GitHub token configured: `true`
  - GitHub OAuth fully configured: `false`
  - Bootstrap admin API key configured: `false`

### 4. Database Snapshot (`data/tracker.db`)

#### Core Table Counts

- `programs`: 606
- `events`: 882
- `github_watches`: 208
- `submissions`: 1
- `scan_jobs`: 14
- `alert_rules`: 3
- `users`: 1
- `pre_audit_findings`: 0
- `program_tags`: 0

#### Program Distribution by Platform

- HackenProof: 308
- Immunefi: 265
- Sherlock: 31
- Code4rena: 2

#### Event Distribution (Top Types)

- `new_program`: 403
- `run_error`: 348
- `program_updated`: 105
- `notification_error`: 21
- `github_updated`: 3

#### Job Health

- Scan job statuses: `done=14`
- Latest event timestamp: `2026-02-28T15:39:39+00:00`

### 5. Storage and Artifacts

- Directory/file sizes:
  - `app/`: 616K
  - `web/`: 96K
  - `data/`: 34M
  - `README.md`: 8.0K
  - `requirements.txt`: 4.0K
- Artifact counts:
  - `data/exports`: 44 files
  - `data/backups`: 23 files
  - `data/evidence`: 1 file
  - `data/reports`: 1 file
- Logs:
  - `data/service.log`: 620B
  - `data/server.log`: 0B

### 6. Operational Notes

- The system has already ingested a substantial program set (606 programs) and created active watch coverage (208 GitHub watches).
- Event history shows successful ingestion alongside frequent `run_error` events, which should be reviewed for reliability hardening.
- Team/user and pre-audit workflows are present structurally, but currently have minimal populated records.
- Integrations for Telegram and GitHub API are enabled, while GitHub OAuth login is not fully configured yet.

### 7. Suggested Next Actions

1. Review the `run_error` events to reduce scan noise and improve successful run ratio.
2. Configure GitHub OAuth variables if browser-based GitHub login is needed.
3. Consider extending `.gitignore` for generated export/backup/log files before long-term repository versioning.
