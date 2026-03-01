# AGENT Setup Guide

This file gives a fast setup path for any collaborator (or coding agent) working in this repository.

## Quick Setup

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

## Required Tools

- Python `3.10+`
- `git`

## Environment

`./scripts/setup.sh` creates `.env` from `.env.example` if missing.

Important variables to set in `.env`:

```env
PORT=3001
TRACK_PLATFORMS=Sherlock,Immunefi,Code4rena,HackenProof
```

Recommended:

```env
GITHUB_TOKEN=ghp_...
```

Optional (Telegram alerts):

```env
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
```

## Health Check

```bash
curl -s http://127.0.0.1:3001/api/health
```

## Full Setup Docs

For complete setup and systemd instructions, see `docs/SETUP.md`.
