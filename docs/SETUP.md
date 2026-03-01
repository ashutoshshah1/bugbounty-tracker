# Setup Guide

This document is for new contributors who need to run the project locally.

## 1. Prerequisites

- Python `3.10+`
- `git`
- Internet access (for API source fetches)

Optional but recommended:

- GitHub personal access token for higher API limits (`GITHUB_TOKEN`)
- Telegram bot token/chat id for notifications

## 2. Clone the repository

```bash
git clone https://github.com/ashutoshshah1/bugbounty-tracker.git
cd bugbounty-tracker
```

## 3. One-command setup

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

What it does:

- Creates `.venv` (if missing)
- Installs dependencies from `requirements.txt`
- Creates `.env` from `.env.example` (if missing)
- Ensures `data/reports` exists

## 4. Configure environment

Edit `.env` and set values you need.

Minimum local fields:

```env
PORT=3001
TRACK_PLATFORMS=Sherlock,Immunefi,Code4rena,HackenProof
```

For Telegram alerts:

```env
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=-1001234567890
```

For reliable GitHub checks (recommended):

```env
GITHUB_TOKEN=ghp_...
```

For website GitHub login:

```env
GITHUB_OAUTH_CLIENT_ID=...
GITHUB_OAUTH_CLIENT_SECRET=...
GITHUB_OAUTH_REDIRECT_URI=http://127.0.0.1:3001/api/auth/github/callback
```

## 5. Run the app

```bash
source .venv/bin/activate
python run.py
```

Open:

- `http://127.0.0.1:3001/app` (dashboard)
- `http://127.0.0.1:3001/api/docs` (API docs)

## 6. Verify everything is healthy

```bash
curl -s http://127.0.0.1:3001/api/health
```

You should see status and scheduler/job metrics.

## 7. Optional: import `programs-fixed.json`

```bash
source .venv/bin/activate
python sync_programs_fixed.py
```

This imports/pins GitHub targets and exports `data/programs_with_github_links.csv`.

## 8. Run as a background service (Linux/systemd)

An example service file exists at `ops/bug-bounty-tracker.service`.

Update paths/user in that file first, then:

```bash
sudo cp ops/bug-bounty-tracker.service /etc/systemd/system/bug-bounty-tracker.service
sudo systemctl daemon-reload
sudo systemctl enable --now bug-bounty-tracker.service
sudo systemctl status bug-bounty-tracker.service
```

## 9. Troubleshooting

- `ModuleNotFoundError`: activate `.venv` and reinstall with `./scripts/setup.sh`.
- Port already in use: change `PORT` in `.env` and restart.
- No GitHub scan results: set `GITHUB_TOKEN` and retry.
- No Telegram alerts: verify both `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.
