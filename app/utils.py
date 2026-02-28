from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_program_hash(program_payload: dict[str, Any]) -> str:
    relevant = {
        "name": program_payload.get("name"),
        "platform": program_payload.get("platform"),
        "handle": program_payload.get("handle"),
        "link": program_payload.get("link"),
        "date_launched": program_payload.get("date_launched"),
        "scope_type": program_payload.get("scope_type"),
        "bounty_min": program_payload.get("bounty_min"),
        "bounty_max": program_payload.get("bounty_max"),
    }
    encoded = repr(sorted(relevant.items())).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def format_reward_range(bounty_min: Any, bounty_max: Any) -> str:
    if bounty_min is None and bounty_max is None:
        return "N/A"

    def _fmt(value: Any) -> str:
        try:
            amount = float(value)
        except (TypeError, ValueError):
            return "N/A"
        if amount.is_integer():
            return f"${int(amount):,}"
        return f"${amount:,.2f}"

    low = _fmt(bounty_min)
    high = _fmt(bounty_max)

    if low == "N/A" and high != "N/A":
        return high
    if high == "N/A" and low != "N/A":
        return low
    if low == high:
        return low
    return f"{low} - {high}"


def parse_github_url(url: str) -> tuple[str, str, str, str] | None:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    parts = [part for part in parsed.path.split("/") if part]

    if host in {"github.com", "www.github.com"}:
        if len(parts) < 2:
            return None

        owner = parts[0]
        repo = parts[1]
        branch = "main"
        file_path = ""

        if len(parts) >= 5 and parts[2] in {"blob", "tree"}:
            branch = parts[3]
            file_path = "/".join(parts[4:])
        return owner, repo, file_path, branch

    if host == "raw.githubusercontent.com":
        if len(parts) < 4:
            return None
        owner = parts[0]
        repo = parts[1]
        branch = parts[2]
        file_path = "/".join(parts[3:])
        return owner, repo, file_path, branch

    return None


def sanitize_filename(filename: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", filename)
    return safe[:140] or "report.pdf"


def extract_pdf_summary(pdf_path: str | Path, max_chars: int = 800) -> str | None:
    from pypdf import PdfReader

    path = Path(pdf_path)
    if not path.exists() or path.suffix.lower() != ".pdf":
        return None

    reader = PdfReader(str(path))
    fragments: list[str] = []
    for index, page in enumerate(reader.pages):
        text = page.extract_text() or ""
        if text.strip():
            fragments.append(text.strip())
        if index >= 1:
            break

    if not fragments:
        return None

    summary = "\n".join(fragments)
    summary = re.sub(r"\s+", " ", summary).strip()
    return summary[:max_chars]
