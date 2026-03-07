# Bug Bounty Program Tracker

Automated tracker for smart-contract bug bounty hunting workflows:

- Web GUI dashboard at `/app` (glassy UI with separate app/backend sections)
- Pulls program data from `https://bbradar.io` and `https://www.vigilseek.com/bug-bounty` (default every 30 minutes)
- Focus filter for `Sherlock`, `Immunefi`, `Code4rena`, and `HackenProof` programs (configurable)
- Detects new programs and changed program details
- De-duplicates vigilseek programs already present in your tracker (by external id/link/name+platform)
- Watches GitHub file/repo targets (default every 60 minutes)
- Sends Telegram alerts for new program launches and updates
- Routes `github_updated` alerts through `GITHUB_TELEGRAM_*` when configured
- Keeps a submissions/triage list with optional PDF report attachment and extracted summary
- Async scan job queue (`job_id` + polling)
- Program diff timeline (field-level and GitHub file changes)
- Hotlist engine (priority score + manual boost tags)
- SLA/deadline reminders and overdue alerts
- Submission intelligence trends + duplicate guard
- Per-platform report templates and validator
- Evidence vault (file/link/tx-hash attachments)
- Team workflow (assignment, transitions, notes, review state)
- Reliability hardening (retry/backoff, source health alerts, API-key hashing, bounded workers, stale-job recovery, housekeeping retention)
- Pre-audit pipeline (AI/manual findings, validation gate, and full report draft generation)

## Quick Start (New Contributors)

```bash
git clone https://github.com/ashutoshshah1/bugbounty-tracker.git
cd bugbounty-tracker
chmod +x scripts/setup.sh
./scripts/setup.sh
source .venv/bin/activate
python run.py
```

Open:

- `http://127.0.0.1:3001/app`
- `http://127.0.0.1:3001/api/docs`

Detailed onboarding guide: [docs/SETUP.md](docs/SETUP.md).
Agent-friendly quick setup: [AGENT.md](AGENT.md).

## 1. Setup

Recommended:

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

Manual setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # skip if .env already exists
```

Set Telegram values in `.env`:

```env
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=-1001234567890
```

Optional separate GitHub-update bot:

```env
GITHUB_TELEGRAM_BOT_TOKEN=123456:DEF...
GITHUB_TELEGRAM_CHAT_ID=-1009876543210
```

Optional (recommended):

```env
GITHUB_TOKEN=ghp_...
```

For large GitHub watch lists, `GITHUB_TOKEN` is effectively required to avoid API rate limits.

Optional source controls:

```env
VIGILSEEK_ENABLED=true
VIGILSEEK_BASE_URL=https://new-api.vigilseek.com
```

For website GitHub login, configure OAuth values:

```env
GITHUB_OAUTH_CLIENT_ID=...
GITHUB_OAUTH_CLIENT_SECRET=...
GITHUB_OAUTH_REDIRECT_URI=http://127.0.0.1:3001/api/auth/github/callback
GITHUB_OAUTH_SCOPE=read:user user:email
```

If `GITHUB_TOKEN` is already configured for local use and OAuth app credentials are absent,
the dashboard `GitHub Login` button will fall back to token-based login and redirect back to `/app`.

## 2. Run

```bash
source .venv/bin/activate
python run.py
```

API and docs:

- `http://127.0.0.1:3001/app` (GUI)
- `http://127.0.0.1:3001/api` (API index)
- `http://127.0.0.1:3001/api/docs` (OpenAPI docs)

## 3. Scheduler Defaults

- `BBRADAR_INTERVAL_MINUTES=30`
- `GITHUB_INTERVAL_MINUTES=60`
- `NOTIFICATION_RETRY_INTERVAL_MINUTES=5`
- `DIGEST_INTERVAL_HOURS=24` (if `DIGEST_ENABLED=true`)
- `BACKUP_INTERVAL_HOURS=24` (if `BACKUP_ENABLED=true`)
- `SLA_REMINDER_INTERVAL_MINUTES=30` (if `SLA_REMINDER_ENABLED=true`)
- `HOUSEKEEPING_INTERVAL_HOURS=6` (if `HOUSEKEEPING_ENABLED=true`)

These jobs run automatically in the background once the app starts.

24/7 queue and retention defaults:

- `JOB_WORKER_COUNT=4`
- `STALE_JOB_TIMEOUT_MINUTES=120`
- `HOUSEKEEPING_ENABLED=true`
- `HOUSEKEEPING_INTERVAL_HOURS=6`
- `EVENT_RETENTION_DAYS=120`
- `JOB_RETENTION_DAYS=30`
- `DATABASE_BUSY_TIMEOUT_MS=5000`

## 4. Key Endpoints

- `GET /api/health`
- `GET /api/auth/github/login?return_to=https://your-frontend/callback`
- `GET /api/auth/github/callback`
- `POST /api/runs/bbradar` (manual run)
- `POST /api/runs/github` (manual run)
- `POST /api/runs/digest` (manual digest run)
- `POST /api/runs/backup` (manual backup/export run)
- `POST /api/runs/sla-reminders` (manual SLA reminder run)
- `POST /api/runs/housekeeping` (manual prune/recovery run)
- `GET /api/jobs` and `GET /api/jobs/{id}` (job queue polling)
- `POST /api/maintenance/cleanup-invalid-watches?min_errors=2&lookback_hours=336&dry_run=true`
- `GET /api/programs?platform=HackenProof&updated_only=true&focus=smart_contract&q=hedera`
- `GET /api/programs/{external_id}` (program detail: events/submissions/watches)
- `GET /api/programs/{external_id}/timeline`
- `GET /api/hotlist`
- `POST /api/program-tags` (admin API key required)
- `GET /api/events`
- `POST /api/github-watches` (add a watched GitHub target)
- `GET /api/github-watches?q=github-text&program_name=program`
- `POST /api/submissions`
- `GET /api/submissions/kanban`
- `POST /api/submissions/duplicate-check`
- `POST /api/submissions/{id}/deadline`
- `GET /api/submissions/deadlines`
- `GET /api/submissions/{id}/workflow`
- `POST /api/submissions/{id}/assign`
- `POST /api/submissions/{id}/transition`
- `POST /api/submissions/{id}/notes`
- `GET /api/submissions/{id}/notes`
- `POST /api/submissions/{id}/evidence`
- `GET /api/submissions/{id}/evidence`
- `POST /api/submissions/upload` (multipart upload with PDF)
- `PATCH /api/submissions/{id}`
- `GET /api/analytics/watch-health`
- `GET /api/analytics/rejections`
- `GET /api/analytics/source-coverage`
- `GET /api/analytics/submission-intelligence`
- `GET /api/templates`
- `POST /api/templates/validate`
- `POST /api/pre-audit/heuristics` (Solidity heuristic scan)
- `GET /api/pre-audit/findings` (admin API key required)
- `POST /api/pre-audit/findings` (admin API key required)
- `POST /api/pre-audit/findings/{id}/validate` (admin API key required)
- `POST /api/pre-audit/findings/{id}/draft-report` (optionally creates submission draft)
- `GET /api/alert-rules`
- `POST /api/alert-rules` (admin API key required)
- `GET /api/team/users` (admin API key required)
- `POST /api/team/users` (admin API key required)

## 5. Example: Add GitHub Watch

```bash
curl -X POST http://127.0.0.1:3001/api/github-watches \
  -H 'Content-Type: application/json' \
  -d '{
    "github_url": "https://github.com/example/protocol/blob/main/contracts/Vault.sol",
    "program_external_id": "HackenProof:example-protocol"
  }'
```

## 6. Notes

- First run seeds existing programs into local DB.
- By default this seed does not send Telegram alerts (`BOOTSTRAP_NOTIFY_EXISTING=false`).
- Program and event data is stored in SQLite at `data/tracker.db`.
- Uploaded PDFs are stored in `data/reports`.
- Optional admin bootstrap:
  - `BOOTSTRAP_ADMIN_USERNAME=owner`
  - `BOOTSTRAP_ADMIN_API_KEY=...` (use this value as `X-API-Key` for admin endpoints)
- Security hardening:
  - API keys are stored hashed (not plaintext)
  - Set `API_KEY_SIGNING_SECRET` to a strong unique value in production
  - Source failure alerts are rate-limited with `SOURCE_ALERT_COOLDOWN_MINUTES`
  - Immunefi `program_updated` alerts are suppressed when only `bounty_min` flips between `0` and non-zero (known noisy upstream pattern)
  - Queue processing uses bounded workers (`JOB_WORKER_COUNT`)
  - Stale queued/running jobs are auto-marked on restart (`STALE_JOB_TIMEOUT_MINUTES`)
  - Background retention cleanup keeps DB size stable (`HOUSEKEEPING_*`, `EVENT_RETENTION_DAYS`, `JOB_RETENTION_DAYS`)

## 7. Import `programs-fixed.json` and pin GitHub checks

```bash
source .venv/bin/activate
python sync_programs_fixed.py
```

This will:

- read `programs-fixed.json`
- extract GitHub URLs from each program `scope`
- pin each GitHub target as an active watch
- export `data/programs_with_github_links.csv`

Optional verification run:

```bash
python sync_programs_fixed.py --scan-github
```

## 8. Run 24/7 with systemd

Service file included at `ops/bug-bounty-tracker.service`.

```bash
sudo cp ops/bug-bounty-tracker.service /etc/systemd/system/bug-bounty-tracker.service
sudo systemctl daemon-reload
sudo systemctl enable --now bug-bounty-tracker.service
sudo systemctl status bug-bounty-tracker.service
```

## 9. Pre-Audit Workflow (Admin)

1. Create finding: `POST /api/pre-audit/findings`
2. Validate finding: `POST /api/pre-audit/findings/{id}/validate`
3. Generate full report draft: `POST /api/pre-audit/findings/{id}/draft-report`
4. Optional Solidity heuristics: `POST /api/pre-audit/heuristics` (`auto_create_findings=true`)
