from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import APIRouter, Body, Cookie, Depends, FastAPI, File, Form, HTTPException, Header, Query, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .api_models import (
    AlertRuleCreate,
    AlertRuleOut,
    AlertRuleUpdate,
    EventOut,
    GithubWatchCreate,
    GithubWatchOut,
    PreAuditFindingCreate,
    PreAuditFindingOut,
    PreAuditFindingUpdate,
    ProgramOut,
    SubmissionCreate,
    SubmissionOut,
    SubmissionUpdate,
    TeamUserCreate,
    TeamUserOut,
    TeamUserUpdate,
)
from .config import Settings
from .database import Database
from .service import TrackerService
from .utils import sanitize_filename, utc_now_iso

settings = Settings.from_env()
db = Database(settings.database_path, busy_timeout_ms=settings.database_busy_timeout_ms)
service = TrackerService(settings=settings, db=db)
scheduler = BackgroundScheduler(timezone=settings.timezone)
WEB_DIR = Path(__file__).resolve().parent.parent / "web"
EVIDENCE_DIR = settings.data_dir / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


@asynccontextmanager
async def lifespan(_: FastAPI):
    service.recover_after_restart()
    scheduler.add_job(
        service.scan_bbradar,
        trigger="interval",
        minutes=settings.bbradar_interval_minutes,
        kwargs={"trigger": "scheduler"},
        id="bbradar_scan",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        next_run_time=datetime.now(timezone.utc) + timedelta(seconds=5),
    )
    scheduler.add_job(
        service.scan_github,
        trigger="interval",
        minutes=settings.github_interval_minutes,
        kwargs={"trigger": "scheduler"},
        id="github_scan",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        next_run_time=datetime.now(timezone.utc) + timedelta(seconds=15),
    )
    if settings.digest_enabled:
        scheduler.add_job(
            service.run_daily_digest,
            trigger="interval",
            hours=settings.digest_interval_hours,
            kwargs={"trigger": "scheduler"},
            id="digest_run",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
            next_run_time=datetime.now(timezone.utc) + timedelta(seconds=25),
        )
    if settings.backup_enabled:
        scheduler.add_job(
            service.run_backup_export,
            trigger="interval",
            hours=settings.backup_interval_hours,
            kwargs={"trigger": "scheduler"},
            id="backup_run",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
            next_run_time=datetime.now(timezone.utc) + timedelta(seconds=35),
        )
    if settings.sla_reminder_enabled:
        scheduler.add_job(
            service.run_sla_reminders,
            trigger="interval",
            minutes=settings.sla_reminder_interval_minutes,
            kwargs={"trigger": "scheduler"},
            id="sla_reminder_run",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
            next_run_time=datetime.now(timezone.utc) + timedelta(seconds=45),
        )
    if settings.housekeeping_enabled:
        scheduler.add_job(
            service.run_housekeeping,
            trigger="interval",
            hours=settings.housekeeping_interval_hours,
            kwargs={"trigger": "scheduler"},
            id="housekeeping_run",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
            next_run_time=datetime.now(timezone.utc) + timedelta(seconds=55),
        )
    scheduler.start()

    try:
        yield
    finally:
        if scheduler.running:
            scheduler.shutdown(wait=False)
        service.close()
        db.close()


app = FastAPI(
    title="Bug Bounty Program Tracker",
    description=(
        "Tracks new/updated bug bounty programs from bbradar, watches GitHub links for changes, "
        "and sends Telegram alerts."
    ),
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)
api = APIRouter(prefix="/api")

app.mount("/web", StaticFiles(directory=str(WEB_DIR)), name="web")


@app.get("/", include_in_schema=False)
def index() -> RedirectResponse:
    return RedirectResponse(url="/app", status_code=307)


@app.get("/app", include_in_schema=False)
def app_dashboard() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/docs", include_in_schema=False)
def docs_redirect() -> RedirectResponse:
    return RedirectResponse(url="/api/docs", status_code=307)


@app.get("/api", include_in_schema=False)
def api_index() -> dict[str, str]:
    return {
        "service": "bug-bounty-tracker-api",
        "app": "/app",
        "docs": "/api/docs",
        "openapi": "/api/openapi.json",
    }


@app.get("/health", include_in_schema=False)
@api.get("/health")
def health() -> dict:
    return service.health()


def _require_active_user(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> dict:
    user = service.authenticate_api_key(x_api_key)
    if user is None:
        raise HTTPException(status_code=401, detail="invalid or missing api key")
    if int(user.get("active") or 0) != 1:
        raise HTTPException(status_code=403, detail="user is disabled")
    return user


def _require_admin_user(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> dict:
    user = _require_active_user(x_api_key)
    if str(user.get("role") or "").casefold() != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return user


def _public_team_user(user: dict) -> dict:
    return {
        "id": int(user.get("id")),
        "username": str(user.get("username") or ""),
        "role": str(user.get("role") or ""),
        "active": int(user.get("active") or 0),
        "created_at": str(user.get("created_at") or ""),
        "updated_at": str(user.get("updated_at") or ""),
    }


def _run_or_queue(job_type: str, *, queued: bool, trigger: str = "manual") -> dict:
    if queued:
        job = service.enqueue_scan_job(job_type=job_type, trigger=trigger)
        return {
            "queued": True,
            "job_id": int(job["id"]),
            "job_type": job_type,
            "status": str(job.get("status") or "queued"),
            "created_at": job.get("created_at"),
        }
    if job_type == "scan_bbradar":
        return service.scan_bbradar(trigger=trigger)
    if job_type == "scan_github":
        return service.scan_github(trigger=trigger)
    if job_type == "digest":
        return service.run_daily_digest(trigger=trigger)
    if job_type == "backup":
        return service.run_backup_export(trigger=trigger)
    if job_type == "sla_reminder":
        return service.run_sla_reminders(trigger=trigger)
    if job_type == "housekeeping":
        return service.run_housekeeping(trigger=trigger)
    raise HTTPException(status_code=400, detail=f"unsupported job_type {job_type}")


def _github_oauth_ready() -> bool:
    return bool(
        settings.github_oauth_client_id
        and settings.github_oauth_client_secret
        and settings.github_oauth_redirect_uri
    )


def _valid_return_url(url: str) -> bool:
    return url.startswith("https://") or url.startswith("http://")


@app.get("/auth/github/login", include_in_schema=False)
@api.get("/auth/github/login")
def github_login(return_to: str | None = Query(default=None)) -> RedirectResponse:
    if not _github_oauth_ready():
        raise HTTPException(
            status_code=503,
            detail=(
                "GitHub OAuth is not configured. Set GITHUB_OAUTH_CLIENT_ID, "
                "GITHUB_OAUTH_CLIENT_SECRET, and GITHUB_OAUTH_REDIRECT_URI."
            ),
        )

    state = secrets.token_urlsafe(24)
    params = {
        "client_id": settings.github_oauth_client_id or "",
        "redirect_uri": settings.github_oauth_redirect_uri or "",
        "scope": settings.github_oauth_scope,
        "state": state,
    }
    auth_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"

    response = RedirectResponse(url=auth_url, status_code=302)
    response.set_cookie("gh_oauth_state", state, httponly=True, samesite="lax", max_age=600)

    if return_to and _valid_return_url(return_to):
        response.set_cookie("gh_oauth_return_to", return_to, httponly=True, samesite="lax", max_age=600)

    return response


@app.get("/auth/github/callback", include_in_schema=False)
@api.get("/auth/github/callback")
def github_callback(
    code: str = Query(...),
    state: str = Query(...),
    gh_oauth_state: str | None = Cookie(default=None),
    gh_oauth_return_to: str | None = Cookie(default=None),
):
    if not _github_oauth_ready():
        raise HTTPException(status_code=503, detail="GitHub OAuth is not configured")

    if not gh_oauth_state or gh_oauth_state != state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    timeout = settings.request_timeout_seconds
    token_response = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={
            "client_id": settings.github_oauth_client_id,
            "client_secret": settings.github_oauth_client_secret,
            "code": code,
            "redirect_uri": settings.github_oauth_redirect_uri,
            "state": state,
        },
        timeout=timeout,
    )
    if not token_response.ok:
        raise HTTPException(
            status_code=502,
            detail=f"GitHub token exchange failed ({token_response.status_code})",
        )

    token_payload = token_response.json()
    access_token = token_payload.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail=f"GitHub OAuth error: {token_payload}")

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {access_token}",
    }
    user_response = requests.get("https://api.github.com/user", headers=headers, timeout=timeout)
    if not user_response.ok:
        raise HTTPException(status_code=502, detail=f"GitHub user fetch failed ({user_response.status_code})")

    user_payload = user_response.json()
    user_info = {
        "id": user_payload.get("id"),
        "login": user_payload.get("login"),
        "name": user_payload.get("name"),
        "avatar_url": user_payload.get("avatar_url"),
        "html_url": user_payload.get("html_url"),
        "email": user_payload.get("email"),
    }

    if gh_oauth_return_to and _valid_return_url(gh_oauth_return_to):
        query = urlencode(
            {
                "github_login": user_info.get("login") or "",
                "github_id": user_info.get("id") or "",
            }
        )
        delimiter = "&" if "?" in gh_oauth_return_to else "?"
        response = RedirectResponse(f"{gh_oauth_return_to}{delimiter}{query}", status_code=302)
        response.delete_cookie("gh_oauth_state")
        response.delete_cookie("gh_oauth_return_to")
        return response

    response = {
        "ok": True,
        "message": (
            "GitHub login succeeded. To return to your frontend automatically, call "
            "/api/auth/github/login?return_to=https://your-site/callback"
        ),
        "github_user": user_info,
    }
    return response


@app.post("/runs/bbradar", include_in_schema=False)
@api.post("/runs/bbradar")
def run_bbradar(queued: bool = Query(default=True)) -> dict:
    return _run_or_queue("scan_bbradar", queued=queued, trigger="manual")


@app.post("/runs/github", include_in_schema=False)
@api.post("/runs/github")
def run_github(queued: bool = Query(default=True)) -> dict:
    return _run_or_queue("scan_github", queued=queued, trigger="manual")


@app.post("/runs/digest", include_in_schema=False)
@api.post("/runs/digest")
def run_digest(queued: bool = Query(default=True)) -> dict:
    return _run_or_queue("digest", queued=queued, trigger="manual")


@app.post("/runs/backup", include_in_schema=False)
@api.post("/runs/backup")
def run_backup(queued: bool = Query(default=True)) -> dict:
    return _run_or_queue("backup", queued=queued, trigger="manual")


@app.post("/runs/sla-reminders", include_in_schema=False)
@api.post("/runs/sla-reminders")
def run_sla_reminders(queued: bool = Query(default=True)) -> dict:
    return _run_or_queue("sla_reminder", queued=queued, trigger="manual")


@app.post("/runs/housekeeping", include_in_schema=False)
@api.post("/runs/housekeeping")
def run_housekeeping(queued: bool = Query(default=True)) -> dict:
    return _run_or_queue("housekeeping", queued=queued, trigger="manual")


@app.get("/jobs", include_in_schema=False)
@api.get("/jobs")
def list_jobs(
    limit: int = Query(default=100, ge=1, le=1000),
    status: str | None = Query(default=None),
) -> list[dict]:
    return service.list_scan_jobs(limit=limit, status=status)


@app.get("/jobs/{job_id}", include_in_schema=False)
@api.get("/jobs/{job_id}")
def get_job(job_id: int) -> dict:
    item = service.get_scan_job(job_id)
    if item is None:
        raise HTTPException(status_code=404, detail="job not found")
    return item


@app.post("/maintenance/cleanup-invalid-watches", include_in_schema=False)
@api.post("/maintenance/cleanup-invalid-watches")
def cleanup_invalid_watches(
    min_errors: int = Query(default=2, ge=1, le=100),
    lookback_hours: int = Query(default=24 * 14, ge=1, le=24 * 365),
    dry_run: bool = Query(default=True),
) -> dict:
    return service.cleanup_invalid_github_watches(
        min_errors=min_errors,
        lookback_hours=lookback_hours,
        dry_run=dry_run,
    )


@app.get("/programs", response_model=list[ProgramOut], include_in_schema=False)
@api.get("/programs", response_model=list[ProgramOut])
def list_programs(
    limit: int = Query(default=100, ge=1, le=1000),
    platform: str | None = None,
    updated_only: bool = False,
    focus: str = Query(default="all", pattern="^(all|smart_contract)$"),
    q: str | None = Query(default=None, max_length=200),
) -> list[dict]:
    return service.list_programs_with_priority(
        limit=limit,
        platform=platform,
        updated_only=updated_only,
        focus=focus,
        q=q,
    )


@app.get("/programs/{external_id}", include_in_schema=False)
@api.get("/programs/{external_id}")
def get_program_detail(
    external_id: str,
    event_limit: int = Query(default=30, ge=1, le=300),
) -> dict:
    detail = service.get_program_detail(external_id=external_id, event_limit=event_limit)
    if detail is None:
        raise HTTPException(status_code=404, detail="program not found")
    return detail


@app.get("/programs/{external_id}/timeline", include_in_schema=False)
@api.get("/programs/{external_id}/timeline")
def program_timeline(
    external_id: str,
    limit: int = Query(default=120, ge=1, le=1000),
) -> list[dict]:
    return service.get_program_timeline(external_id=external_id, limit=limit)


@app.get("/hotlist", include_in_schema=False)
@api.get("/hotlist")
def hotlist_programs(
    limit: int = Query(default=100, ge=1, le=1000),
    focus: str = Query(default="smart_contract", pattern="^(all|smart_contract)$"),
    q: str | None = Query(default=None, max_length=200),
) -> list[dict]:
    return service.list_hotlist_programs(limit=limit, focus=focus, q=q)


@app.get("/program-tags", include_in_schema=False)
@api.get("/program-tags")
def list_program_tags(
    program_external_id: str | None = Query(default=None),
    tag: str | None = Query(default=None),
) -> list[dict]:
    return service.list_program_tags(program_external_id=program_external_id, tag=tag)


@app.post("/program-tags", include_in_schema=False)
@api.post("/program-tags")
def upsert_program_tag(payload: dict = Body(...), user: dict = Depends(_require_admin_user)) -> dict:
    try:
        return service.upsert_program_tag(
            program_external_id=str(payload.get("program_external_id") or ""),
            tag=str(payload.get("tag") or ""),
            note=(payload.get("note") if payload.get("note") is not None else None),
            manual_boost=float(payload.get("manual_boost") or 0.0),
            created_by=str(user.get("username") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/program-tags/{tag_id}", include_in_schema=False)
@api.delete("/program-tags/{tag_id}")
def delete_program_tag(tag_id: int, _: dict = Depends(_require_admin_user)) -> dict[str, str]:
    deleted = service.delete_program_tag(tag_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="tag not found")
    return {"status": "ok", "message": "tag deleted"}


@app.get("/events", response_model=list[EventOut], include_in_schema=False)
@api.get("/events", response_model=list[EventOut])
def list_events(
    limit: int = Query(default=100, ge=1, le=1000),
    event_type: str | None = None,
) -> list[dict]:
    return db.list_events(limit=limit, event_type=event_type)


@app.get("/github-watches", response_model=list[GithubWatchOut], include_in_schema=False)
@api.get("/github-watches", response_model=list[GithubWatchOut])
def list_github_watches(
    active_only: bool = True,
    q: str | None = Query(default=None, max_length=200),
    program_name: str | None = Query(default=None, max_length=200),
) -> list[dict]:
    return db.list_github_watches(active_only=active_only, q=q, program_name=program_name)


@app.post("/github-watches", response_model=GithubWatchOut, include_in_schema=False)
@api.post("/github-watches", response_model=GithubWatchOut)
def create_github_watch(payload: GithubWatchCreate) -> dict:
    try:
        return service.create_github_watch(
            github_url=payload.github_url,
            owner=payload.owner,
            repo=payload.repo,
            file_path=payload.file_path,
            branch=payload.branch,
            program_external_id=payload.program_external_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/github-watches/{watch_id}", include_in_schema=False)
@api.delete("/github-watches/{watch_id}")
def delete_github_watch(watch_id: int) -> dict[str, str]:
    deleted = db.deactivate_github_watch(watch_id=watch_id, now_iso=utc_now_iso())
    if not deleted:
        raise HTTPException(status_code=404, detail="watch not found")
    return {"status": "ok", "message": "watch deactivated"}


@app.get("/submissions", response_model=list[SubmissionOut], include_in_schema=False)
@api.get("/submissions", response_model=list[SubmissionOut])
def list_submissions(
    limit: int = Query(default=100, ge=1, le=1000),
    status: str | None = None,
) -> list[dict]:
    return db.list_submissions(limit=limit, status=status)


@app.post("/submissions/duplicate-check", include_in_schema=False)
@api.post("/submissions/duplicate-check")
def duplicate_check(payload: dict = Body(...)) -> dict:
    return {
        "matches": service.find_submission_duplicates(payload, limit=10),
    }


@app.get("/submissions/kanban", include_in_schema=False)
@api.get("/submissions/kanban")
def submissions_kanban(limit_per_status: int = Query(default=100, ge=1, le=1000)) -> dict:
    return service.list_submissions_kanban(limit_per_status=limit_per_status)


@app.post("/submissions", response_model=SubmissionOut, include_in_schema=False)
@api.post("/submissions", response_model=SubmissionOut)
def create_submission(payload: SubmissionCreate) -> dict:
    try:
        return service.create_submission(payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.patch("/submissions/{submission_id}", response_model=SubmissionOut, include_in_schema=False)
@api.patch("/submissions/{submission_id}", response_model=SubmissionOut)
def update_submission(submission_id: int, payload: SubmissionUpdate) -> dict:
    updates = {key: value for key, value in payload.model_dump().items() if value is not None}
    updated = service.update_submission(submission_id=submission_id, updates=updates)
    if updated is None:
        raise HTTPException(status_code=404, detail="submission not found")
    return updated


@app.post("/submissions/upload", response_model=SubmissionOut, include_in_schema=False)
@api.post("/submissions/upload", response_model=SubmissionOut)
async def create_submission_with_pdf(
    platform: str = Form(...),
    program_name: str = Form(...),
    bug_title: str = Form(...),
    severity: str = Form("unknown"),
    status: str = Form("submitted"),
    submitted_at: str | None = Form(None),
    triage_notes: str | None = Form(None),
    rejection_reason: str | None = Form(None),
    report_pdf: UploadFile | None = File(None),
) -> dict:
    report_path: str | None = None

    if report_pdf is not None:
        safe_name = sanitize_filename(report_pdf.filename or "report.pdf")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        destination = settings.reports_dir / f"{timestamp}_{safe_name}"

        content = await report_pdf.read()
        destination.write_bytes(content)
        report_path = str(destination)

    payload = {
        "platform": platform,
        "program_name": program_name,
        "bug_title": bug_title,
        "severity": severity,
        "status": status,
        "submitted_at": submitted_at,
        "triage_notes": triage_notes,
        "rejection_reason": rejection_reason,
        "report_pdf_path": report_path,
    }
    return service.create_submission(payload)


@app.post("/submissions/{submission_id}/deadline", include_in_schema=False)
@api.post("/submissions/{submission_id}/deadline")
def set_submission_deadline(
    submission_id: int,
    payload: dict = Body(...),
) -> dict:
    try:
        return service.set_submission_deadline(
            submission_id=submission_id,
            due_at=(str(payload.get("due_at")) if payload.get("due_at") else None),
            sla_hours=(int(payload.get("sla_hours")) if payload.get("sla_hours") is not None else None),
            remind_before_minutes=int(payload.get("remind_before_minutes") or 60),
            active=bool(payload.get("active", True)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/submissions/deadlines", include_in_schema=False)
@api.get("/submissions/deadlines")
def list_submission_deadlines(
    active_only: bool = Query(default=True),
    limit: int = Query(default=500, ge=1, le=5000),
) -> list[dict]:
    return service.list_submission_deadlines(active_only=active_only, limit=limit)


@app.get("/submissions/{submission_id}/workflow", include_in_schema=False)
@api.get("/submissions/{submission_id}/workflow")
def get_submission_workflow(submission_id: int) -> dict:
    try:
        return service.get_submission_workflow(submission_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/submissions/{submission_id}/assign", include_in_schema=False)
@api.post("/submissions/{submission_id}/assign")
def assign_submission(
    submission_id: int,
    payload: dict = Body(...),
    _: dict = Depends(_require_active_user),
) -> dict:
    try:
        user_id = payload.get("user_id")
        return service.assign_submission(
            submission_id=submission_id,
            user_id=int(user_id) if user_id is not None else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/submissions/{submission_id}/transition", include_in_schema=False)
@api.post("/submissions/{submission_id}/transition")
def transition_submission(
    submission_id: int,
    payload: dict = Body(...),
    _: dict = Depends(_require_active_user),
) -> dict:
    try:
        return service.transition_submission(
            submission_id=submission_id,
            new_stage=str(payload.get("stage") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/submissions/{submission_id}/review", include_in_schema=False)
@api.post("/submissions/{submission_id}/review")
def set_submission_review(
    submission_id: int,
    payload: dict = Body(...),
    user: dict = Depends(_require_active_user),
) -> dict:
    try:
        return service.set_submission_review_state(
            submission_id=submission_id,
            approved=bool(payload.get("approved")),
            reviewer_user_id=int(user.get("id")) if user.get("id") is not None else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/submissions/{submission_id}/notes", include_in_schema=False)
@api.get("/submissions/{submission_id}/notes")
def list_submission_notes(
    submission_id: int,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[dict]:
    return service.list_submission_notes(submission_id, limit=limit)


@app.post("/submissions/{submission_id}/notes", include_in_schema=False)
@api.post("/submissions/{submission_id}/notes")
def add_submission_note(
    submission_id: int,
    payload: dict = Body(...),
    user: dict = Depends(_require_active_user),
) -> dict:
    try:
        return service.add_submission_note(
            submission_id=submission_id,
            note=str(payload.get("note") or ""),
            author_user_id=int(user.get("id")) if user.get("id") is not None else None,
            visibility=str(payload.get("visibility") or "internal"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/submissions/{submission_id}/evidence", include_in_schema=False)
@api.get("/submissions/{submission_id}/evidence")
def list_submission_evidence(
    submission_id: int,
    limit: int = Query(default=200, ge=1, le=2000),
) -> list[dict]:
    return service.list_submission_evidence(submission_id, limit=limit)


@app.post("/submissions/{submission_id}/evidence", include_in_schema=False)
@api.post("/submissions/{submission_id}/evidence")
async def add_submission_evidence(
    submission_id: int,
    title: str = Form(...),
    tx_hash: str | None = Form(None),
    external_url: str | None = Form(None),
    notes: str | None = Form(None),
    evidence_file: UploadFile | None = File(None),
    user: dict = Depends(_require_active_user),
) -> dict:
    file_path: str | None = None
    file_type: str | None = None
    if evidence_file is not None:
        safe_name = sanitize_filename(evidence_file.filename or "evidence.bin")
        target_dir = EVIDENCE_DIR / str(submission_id)
        target_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        destination = target_dir / f"{timestamp}_{safe_name}"
        file_path = str(destination)
        file_type = evidence_file.content_type
        destination.write_bytes(await evidence_file.read())
    try:
        return service.add_submission_evidence(
            submission_id=submission_id,
            title=title,
            file_path=file_path,
            file_type=file_type,
            tx_hash=tx_hash,
            external_url=external_url,
            notes=notes,
            created_by=str(user.get("username") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/submissions/evidence/{evidence_id}", include_in_schema=False)
@api.delete("/submissions/evidence/{evidence_id}")
def delete_submission_evidence(evidence_id: int, _: dict = Depends(_require_active_user)) -> dict[str, str]:
    deleted = service.delete_submission_evidence(evidence_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="evidence not found")
    return {"status": "ok", "message": "evidence deleted"}


@app.get("/analytics/rejections", include_in_schema=False)
@api.get("/analytics/rejections")
def rejection_analytics(top_n: int = Query(default=10, ge=1, le=100)) -> dict:
    return service.get_rejection_analytics(top_n=top_n)


@app.get("/analytics/submission-intelligence", include_in_schema=False)
@api.get("/analytics/submission-intelligence")
def submission_intelligence(months: int = Query(default=6, ge=1, le=36)) -> dict:
    return service.get_submission_intelligence(months=months)


@app.get("/analytics/watch-health", include_in_schema=False)
@api.get("/analytics/watch-health")
def watch_health(
    lookback_hours: int = Query(default=24 * 7, ge=1, le=24 * 365),
    stale_hours: int = Query(default=48, ge=1, le=24 * 365),
) -> dict:
    return service.get_watch_health(lookback_hours=lookback_hours, stale_hours=stale_hours)


@app.get("/analytics/source-coverage", include_in_schema=False)
@api.get("/analytics/source-coverage")
def source_coverage() -> dict:
    return service.get_source_coverage()


@app.get("/templates", include_in_schema=False)
@api.get("/templates")
def list_templates() -> list[dict]:
    return service.list_report_templates()


@app.get("/templates/{platform}", include_in_schema=False)
@api.get("/templates/{platform}")
def get_template(platform: str) -> dict:
    return service.get_report_template(platform)


@app.post("/templates/validate", include_in_schema=False)
@api.post("/templates/validate")
def validate_template(payload: dict = Body(...)) -> dict:
    return service.validate_report_template(
        platform=str(payload.get("platform") or ""),
        report_text=str(payload.get("report_text") or ""),
    )


@app.get("/pre-audit/findings", response_model=list[PreAuditFindingOut], include_in_schema=False)
@api.get("/pre-audit/findings", response_model=list[PreAuditFindingOut])
def list_pre_audit_findings(
    limit: int = Query(default=200, ge=1, le=5000),
    status: str | None = Query(default=None),
    platform: str | None = Query(default=None),
    program_external_id: str | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    _: dict = Depends(_require_admin_user),
) -> list[dict]:
    try:
        return service.list_pre_audit_findings(
            limit=limit,
            status=status,
            platform=platform,
            program_external_id=program_external_id,
            q=q,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/pre-audit/findings", response_model=PreAuditFindingOut, include_in_schema=False)
@api.post("/pre-audit/findings", response_model=PreAuditFindingOut)
def create_pre_audit_finding(payload: PreAuditFindingCreate, user: dict = Depends(_require_admin_user)) -> dict:
    try:
        return service.create_pre_audit_finding(
            payload.model_dump(),
            actor_user_id=int(user.get("id")) if user.get("id") is not None else None,
            actor_username=str(user.get("username") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/pre-audit/findings/{finding_id}", include_in_schema=False)
@api.get("/pre-audit/findings/{finding_id}")
def get_pre_audit_finding(finding_id: int, _: dict = Depends(_require_admin_user)) -> dict:
    detail = service.get_pre_audit_finding_detail(finding_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return detail


@app.patch("/pre-audit/findings/{finding_id}", response_model=PreAuditFindingOut, include_in_schema=False)
@api.patch("/pre-audit/findings/{finding_id}", response_model=PreAuditFindingOut)
def update_pre_audit_finding(
    finding_id: int,
    payload: PreAuditFindingUpdate,
    user: dict = Depends(_require_admin_user),
) -> dict:
    updates = {key: value for key, value in payload.model_dump().items() if value is not None}
    try:
        updated = service.update_pre_audit_finding(
            finding_id=finding_id,
            updates=updates,
            actor_user_id=int(user.get("id")) if user.get("id") is not None else None,
            actor_username=str(user.get("username") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if updated is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return updated


@app.post("/pre-audit/findings/{finding_id}/validate", include_in_schema=False)
@api.post("/pre-audit/findings/{finding_id}/validate")
def validate_pre_audit_finding(
    finding_id: int,
    payload: dict = Body(default={}),
    user: dict = Depends(_require_admin_user),
) -> dict:
    updates: dict[str, Any] = {"status": "validated"}
    if payload.get("recommendation") is not None:
        updates["recommendation"] = str(payload.get("recommendation") or "")
    try:
        updated = service.update_pre_audit_finding(
            finding_id=finding_id,
            updates=updates,
            actor_user_id=int(user.get("id")) if user.get("id") is not None else None,
            actor_username=str(user.get("username") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if updated is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return {"status": "ok", "finding": updated}


@app.post("/pre-audit/findings/{finding_id}/draft-report", include_in_schema=False)
@api.post("/pre-audit/findings/{finding_id}/draft-report")
def draft_pre_audit_report(
    finding_id: int,
    payload: dict = Body(default={}),
    user: dict = Depends(_require_admin_user),
) -> dict:
    try:
        return service.generate_pre_audit_report(
            finding_id=finding_id,
            actor_user_id=int(user.get("id")) if user.get("id") is not None else None,
            actor_username=str(user.get("username") or ""),
            create_submission_draft=bool(payload.get("create_submission_draft", False)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/pre-audit/heuristics", include_in_schema=False)
@api.post("/pre-audit/heuristics")
def run_pre_audit_heuristics(
    payload: dict = Body(...),
    user: dict = Depends(_require_admin_user),
) -> dict:
    source_code = str(payload.get("source_code") or "")
    language = str(payload.get("language") or "solidity")
    auto_create = bool(payload.get("auto_create_findings", False))
    try:
        result = service.run_pre_audit_heuristics(source_code=source_code, language=language)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if auto_create and result.get("findings"):
        created: list[dict] = []
        for item in result.get("findings", []):
            finding_payload = {
                "program_external_id": payload.get("program_external_id"),
                "platform": payload.get("platform"),
                "program_name": payload.get("program_name"),
                "title": item.get("title"),
                "severity": item.get("severity"),
                "status": "triage",
                "category": item.get("category"),
                "description": item.get("description"),
                "impact": (
                    "Potential vulnerability pattern detected by heuristic scanner. "
                    "Requires manual validation and exploitability confirmation."
                ),
                "poc_steps": f"Review source around line {item.get('line')}: `{item.get('snippet')}`",
                "recommendation": item.get("recommendation"),
                "source": "codex_chatgpt_heuristics",
                "source_reference": payload.get("source_reference"),
                "target_github_url": payload.get("target_github_url"),
                "ai_confidence": item.get("ai_confidence"),
                "tags": [item.get("heuristic_id"), "heuristic"],
            }
            try:
                created_item = service.create_pre_audit_finding(
                    finding_payload,
                    actor_user_id=int(user.get("id")) if user.get("id") is not None else None,
                    actor_username=str(user.get("username") or ""),
                )
                created.append(created_item)
            except ValueError:
                continue
        result["created_findings"] = created
        result["created_count"] = len(created)
    else:
        result["created_findings"] = []
        result["created_count"] = 0

    return result


@app.get("/alert-rules", response_model=list[AlertRuleOut], include_in_schema=False)
@api.get("/alert-rules", response_model=list[AlertRuleOut])
def list_alert_rules(enabled_only: bool = Query(default=False)) -> list[dict]:
    return service.list_alert_rules(enabled_only=enabled_only)


@app.post("/alert-rules", response_model=AlertRuleOut, include_in_schema=False)
@api.post("/alert-rules", response_model=AlertRuleOut)
def create_alert_rule(payload: AlertRuleCreate, _: dict = Depends(_require_admin_user)) -> dict:
    return service.create_alert_rule(payload.model_dump())


@app.patch("/alert-rules/{rule_id}", response_model=AlertRuleOut, include_in_schema=False)
@api.patch("/alert-rules/{rule_id}", response_model=AlertRuleOut)
def update_alert_rule(
    rule_id: int,
    payload: AlertRuleUpdate,
    _: dict = Depends(_require_admin_user),
) -> dict:
    updates = {key: value for key, value in payload.model_dump().items() if value is not None}
    updated = service.update_alert_rule(rule_id=rule_id, updates=updates)
    if updated is None:
        raise HTTPException(status_code=404, detail="alert rule not found")
    return updated


@app.delete("/alert-rules/{rule_id}", include_in_schema=False)
@api.delete("/alert-rules/{rule_id}")
def delete_alert_rule(rule_id: int, _: dict = Depends(_require_admin_user)) -> dict[str, str]:
    deleted = service.delete_alert_rule(rule_id=rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="alert rule not found")
    return {"status": "ok", "message": "alert rule deleted"}


@app.get("/team/me", include_in_schema=False)
@api.get("/team/me")
def team_me(user: dict = Depends(_require_active_user)) -> dict:
    return _public_team_user(user)


@app.get("/team/users", response_model=list[TeamUserOut], include_in_schema=False)
@api.get("/team/users", response_model=list[TeamUserOut])
def list_team_users(
    active_only: bool = Query(default=False),
    _: dict = Depends(_require_admin_user),
) -> list[dict]:
    return [_public_team_user(item) for item in service.list_team_users(active_only=active_only)]


@app.post("/team/users", include_in_schema=False)
@api.post("/team/users")
def create_team_user(payload: TeamUserCreate, _: dict = Depends(_require_admin_user)) -> dict:
    created = service.create_team_user(username=payload.username, role=payload.role, active=payload.active)
    return {
        "user": _public_team_user(created),
        "api_key": str(created.get("api_key") or ""),
    }


@app.patch("/team/users/{user_id}", response_model=TeamUserOut, include_in_schema=False)
@api.patch("/team/users/{user_id}", response_model=TeamUserOut)
def update_team_user(
    user_id: int,
    payload: TeamUserUpdate,
    _: dict = Depends(_require_admin_user),
) -> dict:
    updates = {key: value for key, value in payload.model_dump().items() if value is not None}
    updated = service.update_team_user(user_id=user_id, updates=updates)
    if updated is None:
        raise HTTPException(status_code=404, detail="user not found")
    return _public_team_user(updated)


@app.post("/team/users/{user_id}/rotate-key", include_in_schema=False)
@api.post("/team/users/{user_id}/rotate-key")
def rotate_team_user_key(user_id: int, _: dict = Depends(_require_admin_user)) -> dict:
    updated = service.rotate_team_user_api_key(user_id=user_id)
    if updated is None:
        raise HTTPException(status_code=404, detail="user not found")
    return {
        "user": _public_team_user(updated),
        "api_key": str(updated.get("api_key") or ""),
    }


@app.delete("/team/users/{user_id}", include_in_schema=False)
@api.delete("/team/users/{user_id}")
def delete_team_user(user_id: int, _: dict = Depends(_require_admin_user)) -> dict[str, str]:
    deleted = service.delete_team_user(user_id=user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="user not found")
    return {"status": "ok", "message": "team user deleted"}


app.include_router(api)
