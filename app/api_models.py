from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator


class ProgramOut(BaseModel):
    id: int
    source: str
    external_id: str
    handle: str
    platform: str
    name: str
    link: str | None
    date_launched: str | None
    scope_type: str | None
    bounty_min: float | None
    bounty_max: float | None
    first_seen_at: str
    last_seen_at: str
    last_changed_at: str
    raw: dict[str, Any]
    priority_score: float | None = None


class EventOut(BaseModel):
    id: int
    event_type: str
    title: str
    details: dict[str, Any]
    program_external_id: str | None
    created_at: str
    notified: int


class RunSummary(BaseModel):
    status: str
    trigger: str
    started_at: str | None = None
    tracked_programs: int | None = None
    tracked_watches: int | None = None
    created: int | None = None
    updated: int | None = None
    unchanged: int | None = None
    baseline: int | None = None
    changed: int | None = None
    errors: int | None = None
    notifications: int | None = None
    rate_limited: bool | None = None
    error: str | None = None
    reason: str | None = None


class GithubWatchCreate(BaseModel):
    github_url: str | None = None
    owner: str | None = None
    repo: str | None = None
    file_path: str = ""
    branch: str = "main"
    program_external_id: str | None = None

    @model_validator(mode="after")
    def validate_sources(self) -> "GithubWatchCreate":
        has_url = bool(self.github_url)
        has_owner_repo = bool(self.owner and self.repo)

        if not has_url and not has_owner_repo:
            raise ValueError("provide github_url or owner+repo")

        return self


class GithubWatchOut(BaseModel):
    id: int
    program_external_id: str | None
    program_name: str | None = None
    repo_owner: str
    repo_name: str
    file_path: str
    branch: str
    last_sha: str | None
    last_checked_at: str | None
    active: int
    github_url: str | None = None
    metadata: dict[str, Any]
    created_at: str
    updated_at: str
    bootstrap_error: str | None = None


class SubmissionCreate(BaseModel):
    platform: str = Field(min_length=1)
    program_name: str = Field(min_length=1)
    bug_title: str = Field(min_length=1)
    severity: str = "unknown"
    status: str = "submitted"
    submitted_at: str | None = None
    triage_notes: str | None = None
    rejection_reason: str | None = None
    report_pdf_path: str | None = None
    pdf_summary: str | None = None


class SubmissionUpdate(BaseModel):
    platform: str | None = None
    program_name: str | None = None
    bug_title: str | None = None
    severity: str | None = None
    status: str | None = None
    submitted_at: str | None = None
    triage_notes: str | None = None
    rejection_reason: str | None = None
    report_pdf_path: str | None = None
    pdf_summary: str | None = None


class SubmissionOut(BaseModel):
    id: int
    platform: str
    program_name: str
    bug_title: str
    severity: str
    status: str
    submitted_at: str | None
    triage_notes: str | None
    rejection_reason: str | None
    report_pdf_path: str | None
    pdf_summary: str | None
    created_at: str
    updated_at: str


class AlertRuleCreate(BaseModel):
    name: str = Field(min_length=1)
    enabled: bool = True
    min_bounty: float | None = None
    platforms: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    event_types: list[str] = Field(default_factory=lambda: ["new_program", "program_updated", "github_updated"])
    digest_only: bool = False


class AlertRuleUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    min_bounty: float | None = None
    platforms: list[str] | None = None
    keywords: list[str] | None = None
    event_types: list[str] | None = None
    digest_only: bool | None = None


class AlertRuleOut(BaseModel):
    id: int
    name: str
    enabled: int
    min_bounty: float | None
    platforms: list[str]
    keywords: list[str]
    event_types: list[str]
    digest_only: int
    created_at: str
    updated_at: str


class TeamUserCreate(BaseModel):
    username: str = Field(min_length=1)
    role: str = Field(pattern="^(admin|analyst|viewer)$")
    active: bool = True


class TeamUserUpdate(BaseModel):
    username: str | None = None
    role: str | None = Field(default=None, pattern="^(admin|analyst|viewer)$")
    active: bool | None = None


class TeamUserOut(BaseModel):
    id: int
    username: str
    role: str
    active: int
    created_at: str
    updated_at: str


class PreAuditFindingCreate(BaseModel):
    program_external_id: str | None = None
    platform: str | None = None
    program_name: str | None = None
    title: str = Field(min_length=1)
    severity: str = "medium"
    status: str = "new"
    category: str | None = None
    description: str = Field(min_length=1)
    impact: str | None = None
    poc_steps: str | None = None
    recommendation: str | None = None
    source: str = "codex_chatgpt"
    source_reference: str | None = None
    target_github_url: str | None = None
    ai_confidence: float | None = None
    tags: list[str] = Field(default_factory=list)


class PreAuditFindingUpdate(BaseModel):
    program_external_id: str | None = None
    platform: str | None = None
    program_name: str | None = None
    title: str | None = None
    severity: str | None = None
    status: str | None = None
    category: str | None = None
    description: str | None = None
    impact: str | None = None
    poc_steps: str | None = None
    recommendation: str | None = None
    source: str | None = None
    source_reference: str | None = None
    target_github_url: str | None = None
    ai_confidence: float | None = None
    tags: list[str] | None = None
    report_markdown: str | None = None
    linked_submission_id: int | None = None


class PreAuditFindingOut(BaseModel):
    id: int
    program_external_id: str | None
    platform: str | None
    program_name: str | None
    title: str
    severity: str
    status: str
    category: str | None
    description: str
    impact: str | None
    poc_steps: str | None
    recommendation: str | None
    source: str
    source_reference: str | None
    target_github_url: str | None
    ai_confidence: float | None
    tags: list[str]
    report_markdown: str | None
    linked_submission_id: int | None
    created_by_user_id: int | None
    created_by_username: str | None
    validated_by_user_id: int | None
    validated_by_username: str | None
    validated_at: str | None
    created_at: str
    updated_at: str
