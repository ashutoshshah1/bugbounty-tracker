from __future__ import annotations

import hashlib
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class GitHubClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        api_message: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.api_message = api_message


class GitHubClient:
    def __init__(self, token: str | None = None, timeout_seconds: int = 30) -> None:
        self.base_url = "https://api.github.com"
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.6,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods={"GET"},
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.headers.update({"Accept": "application/vnd.github+json"})
        if token:
            self.session.headers.update({"Authorization": f"Bearer {token}"})

    def close(self) -> None:
        self.session.close()

    def _request(self, path: str, params: dict[str, Any] | None = None) -> requests.Response:
        response = self.session.get(f"{self.base_url}{path}", params=params, timeout=self.timeout_seconds)
        if response.ok:
            return response

        message = response.text.strip()
        if response.headers.get("content-type", "").startswith("application/json"):
            json_payload = response.json()
            message = json_payload.get("message", message)

        raise GitHubClientError(
            f"GitHub request failed ({response.status_code}): {message}",
            status_code=response.status_code,
            api_message=message,
        )

    def _fetch_target_state_raw(self, owner: str, repo: str, file_path: str, branch: str) -> dict[str, str]:
        cleaned_path = file_path.strip("/")
        if cleaned_path:
            response = self._request(
                f"/repos/{owner}/{repo}/contents/{cleaned_path}",
                params={"ref": branch},
            )
            payload = response.json()

            if isinstance(payload, list):
                digest_source = "|".join(
                    sorted(f"{item.get('path', '')}:{item.get('sha', '')}" for item in payload)
                )
                synthetic_sha = hashlib.sha256(digest_source.encode("utf-8")).hexdigest()
                html_url = f"https://github.com/{owner}/{repo}/tree/{branch}/{cleaned_path}"
                return {"sha": synthetic_sha, "html_url": html_url, "kind": "directory"}

            sha = payload.get("sha")
            html_url = payload.get("html_url")
            if not sha:
                raise GitHubClientError("GitHub contents payload did not include sha")
            return {
                "sha": str(sha),
                "html_url": str(html_url or f"https://github.com/{owner}/{repo}/blob/{branch}/{cleaned_path}"),
                "kind": str(payload.get("type", "file")),
            }

        response = self._request(f"/repos/{owner}/{repo}/commits/{branch}")
        payload = response.json()
        sha = payload.get("sha")
        html_url = payload.get("html_url")
        if not sha:
            raise GitHubClientError("GitHub commit payload did not include sha")

        return {
            "sha": str(sha),
            "html_url": str(html_url or f"https://github.com/{owner}/{repo}/commits/{branch}"),
            "kind": "branch",
        }

    @staticmethod
    def _is_bad_ref_error(exc: GitHubClientError) -> bool:
        if exc.status_code not in {404, 422}:
            return False
        message = (exc.api_message or str(exc)).casefold()
        return "no commit found" in message or "for the ref" in message

    def _get_default_branch(self, owner: str, repo: str) -> str | None:
        payload = self._request(f"/repos/{owner}/{repo}").json()
        branch = payload.get("default_branch")
        if isinstance(branch, str) and branch.strip():
            return branch.strip()
        return None

    def fetch_target_state(self, owner: str, repo: str, file_path: str, branch: str) -> dict[str, str]:
        try:
            return self._fetch_target_state_raw(owner=owner, repo=repo, file_path=file_path, branch=branch)
        except GitHubClientError as exc:
            if not self._is_bad_ref_error(exc):
                raise

            default_branch = self._get_default_branch(owner=owner, repo=repo)
            if not default_branch or default_branch == branch:
                raise

            state = self._fetch_target_state_raw(
                owner=owner,
                repo=repo,
                file_path=file_path,
                branch=default_branch,
            )
            state["resolved_branch"] = default_branch
            state["requested_branch"] = branch
            return state

    def fetch_commit_changed_files(
        self,
        owner: str,
        repo: str,
        old_sha: str,
        new_sha: str,
        max_files: int = 25,
    ) -> list[dict[str, str]]:
        if not old_sha or not new_sha or old_sha == new_sha:
            return []

        files: list[dict[str, Any]] = []

        try:
            compare = self._request(
                f"/repos/{owner}/{repo}/compare/{old_sha}...{new_sha}",
            ).json()
            raw_files = compare.get("files") or []
            if isinstance(raw_files, list):
                files = [item for item in raw_files if isinstance(item, dict)]
        except GitHubClientError:
            files = []

        if not files:
            commit = self._request(f"/repos/{owner}/{repo}/commits/{new_sha}").json()
            raw_files = commit.get("files") or []
            if isinstance(raw_files, list):
                files = [item for item in raw_files if isinstance(item, dict)]

        cleaned: list[dict[str, str]] = []
        for item in files[: max(1, max_files)]:
            filename = str(item.get("filename") or "").strip()
            status = str(item.get("status") or "modified").strip()
            if not filename:
                continue
            cleaned.append({"filename": filename, "status": status})
        return cleaned
