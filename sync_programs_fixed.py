from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from app.config import Settings
from app.database import Database
from app.service import TrackerService
from app.utils import parse_github_url, utc_now_iso

STOPWORDS = {
    "smart",
    "contract",
    "contracts",
    "web",
    "mobile",
    "app",
    "apps",
    "api",
    "protocol",
}


def _canonical_name(name: str) -> str:
    text = name.casefold().replace("&", " and ")
    text = re.sub(r"[^a-z0-9]+", " ", text)
    tokens = [token for token in text.split() if token and token not in STOPWORDS]
    return " ".join(tokens)


def _extract_github_urls(scope: Any) -> list[str]:
    if not isinstance(scope, list):
        return []

    urls: list[str] = []
    for value in scope:
        if not isinstance(value, str):
            continue
        value = value.strip()
        if not value:
            continue
        lowered = value.casefold()
        if "github.com/" in lowered or "raw.githubusercontent.com/" in lowered:
            urls.append(value)
    return urls


def _build_name_indexes(programs: list[dict[str, Any]]) -> tuple[dict[str, str], dict[str, str]]:
    exact: dict[str, str] = {}
    canonical_buckets: dict[str, list[str]] = defaultdict(list)

    for item in programs:
        name = str(item.get("name") or "").strip()
        external_id = str(item.get("external_id") or "").strip()
        if not name or not external_id:
            continue
        exact[name.casefold()] = external_id
        canonical_buckets[_canonical_name(name)].append(external_id)

    canonical_unique = {
        key: values[0]
        for key, values in canonical_buckets.items()
        if key and len(set(values)) == 1
    }
    return exact, canonical_unique


def run_sync(json_path: Path, export_path: Path, run_github_scan: bool) -> int:
    settings = Settings.from_env()
    db = Database(settings.database_path)
    service = TrackerService(settings=settings, db=db)

    now_iso = utc_now_iso()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("programs-fixed.json must contain a JSON array")

    known_programs = db.list_programs(limit=100000)
    exact_index, canonical_index = _build_name_indexes(known_programs)

    existing_watches = {
        (
            str(item["repo_owner"]).casefold(),
            str(item["repo_name"]).casefold(),
            str(item["file_path"]),
            str(item["branch"]),
        )
        for item in db.list_github_watches(active_only=False)
    }

    imported_links = 0
    skipped_invalid = 0
    pinned_new = 0
    pinned_existing = 0
    matched_exact = 0
    matched_canonical = 0
    unmatched_programs: set[str] = set()

    export_rows: list[dict[str, Any]] = []

    for item in payload:
        if not isinstance(item, dict):
            continue

        program_name = str(item.get("name") or "").strip()
        if not program_name:
            continue

        github_urls = _extract_github_urls(item.get("scope"))
        if not github_urls:
            continue

        external_id: str | None = None
        match_type = "unmatched"

        exact_key = program_name.casefold()
        if exact_key in exact_index:
            external_id = exact_index[exact_key]
            match_type = "exact"
            matched_exact += 1
        else:
            canonical_key = _canonical_name(program_name)
            external_id = canonical_index.get(canonical_key)
            if external_id:
                match_type = "canonical"
                matched_canonical += 1
            else:
                unmatched_programs.add(program_name)

        seen_watch_keys_for_program: set[tuple[str, str, str, str]] = set()

        for github_url in github_urls:
            parsed = parse_github_url(github_url)
            if not parsed:
                skipped_invalid += 1
                continue

            owner, repo, file_path, branch = parsed
            watch_key = (owner.casefold(), repo.casefold(), file_path, branch)

            # Deduplicate repeated URL paths per program entry.
            if watch_key in seen_watch_keys_for_program:
                continue
            seen_watch_keys_for_program.add(watch_key)

            metadata = {
                "source": "programs-fixed.json",
                "pinned": True,
                "program_name": program_name,
                "program_start_date": item.get("start_date"),
                "program_last_updated": item.get("last_updated"),
                "source_url": github_url,
                "match_type": match_type,
            }

            watch = db.add_github_watch(
                program_external_id=external_id,
                repo_owner=owner,
                repo_name=repo,
                file_path=file_path,
                branch=branch,
                metadata=metadata,
                now_iso=now_iso,
            )

            if watch_key in existing_watches:
                pinned_existing += 1
            else:
                pinned_new += 1
                existing_watches.add(watch_key)

            imported_links += 1

            export_rows.append(
                {
                    "program_name": program_name,
                    "program_external_id": external_id or "",
                    "match_type": match_type,
                    "github_url": github_url,
                    "repo_owner": owner,
                    "repo_name": repo,
                    "branch": branch,
                    "file_path": file_path,
                    "watch_id": watch["id"],
                }
            )

    export_path.parent.mkdir(parents=True, exist_ok=True)
    with export_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "program_name",
                "program_external_id",
                "match_type",
                "github_url",
                "repo_owner",
                "repo_name",
                "branch",
                "file_path",
                "watch_id",
            ],
        )
        writer.writeheader()
        writer.writerows(export_rows)

    print("SYNC_SUMMARY")
    print(f"  source_file: {json_path}")
    print(f"  export_file: {export_path}")
    print(f"  db_programs_known: {len(known_programs)}")
    print(f"  github_links_imported: {imported_links}")
    print(f"  pinned_new_watches: {pinned_new}")
    print(f"  pinned_existing_watches: {pinned_existing}")
    print(f"  matched_programs_exact: {matched_exact}")
    print(f"  matched_programs_canonical: {matched_canonical}")
    print(f"  unmatched_program_names: {len(unmatched_programs)}")
    print(f"  invalid_or_unsupported_urls: {skipped_invalid}")

    if unmatched_programs:
        print("\nUNMATCHED_PROGRAM_SAMPLE")
        for name in sorted(unmatched_programs)[:20]:
            print(f"  - {name}")

    if run_github_scan:
        print("\nGITHUB_SCAN")
        scan_summary = service.scan_github(trigger="programs-fixed-sync")
        for key, value in scan_summary.items():
            print(f"  {key}: {value}")

    service.close()
    db.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import GitHub scopes from programs-fixed.json and pin GitHub watches.",
    )
    parser.add_argument(
        "--input",
        default="programs-fixed.json",
        help="Path to programs-fixed JSON file.",
    )
    parser.add_argument(
        "--export",
        default="data/programs_with_github_links.csv",
        help="CSV export path for program-to-GitHub mapping.",
    )
    parser.add_argument(
        "--scan-github",
        action="store_true",
        help="Run a GitHub scan after pinning watches.",
    )
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"input file not found: {input_path}")

    export_path = Path(args.export).expanduser().resolve()
    return run_sync(input_path, export_path, run_github_scan=bool(args.scan_github))


if __name__ == "__main__":
    raise SystemExit(main())
