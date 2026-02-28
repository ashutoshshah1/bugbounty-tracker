from __future__ import annotations

from typing import Any

import requests


class BBRadarClientError(RuntimeError):
    """Raised when bbradar data cannot be fetched."""


class BBRadarClient:
    def __init__(self, base_url: str, timeout_seconds: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()
        self._csrf_token: str | None = None

    def close(self) -> None:
        self.session.close()

    def _refresh_csrf_token(self) -> str:
        frontend_response = self.session.get(
            f"{self.base_url}/api/frontend-token",
            timeout=self.timeout_seconds,
        )
        if not frontend_response.ok:
            raise BBRadarClientError(
                f"frontend-token request failed with status {frontend_response.status_code}"
            )

        frontend_token = frontend_response.json().get("frontend_token")
        if not frontend_token:
            raise BBRadarClientError("frontend-token response did not include frontend_token")

        csrf_response = self.session.post(
            f"{self.base_url}/api/csrf-token",
            json={"frontend_token": frontend_token},
            timeout=self.timeout_seconds,
        )
        if not csrf_response.ok:
            raise BBRadarClientError(
                f"csrf-token request failed with status {csrf_response.status_code}"
            )

        csrf_token = csrf_response.json().get("csrf_token")
        if not csrf_token:
            raise BBRadarClientError("csrf-token response did not include csrf_token")

        self._csrf_token = csrf_token
        return csrf_token

    def _get_csrf_token(self) -> str:
        if self._csrf_token:
            return self._csrf_token
        return self._refresh_csrf_token()

    def fetch_programs(self) -> list[dict[str, Any]]:
        csrf_token = self._get_csrf_token()
        headers = {"Content-Type": "application/json", "X-CSRF-Token": csrf_token}

        response = self.session.get(
            f"{self.base_url}/api/programs",
            headers=headers,
            timeout=self.timeout_seconds,
        )

        if response.status_code == 403:
            csrf_token = self._refresh_csrf_token()
            headers["X-CSRF-Token"] = csrf_token
            response = self.session.get(
                f"{self.base_url}/api/programs",
                headers=headers,
                timeout=self.timeout_seconds,
            )

        if not response.ok:
            raise BBRadarClientError(f"program fetch failed with status {response.status_code}")

        payload = response.json()
        if not isinstance(payload, list):
            raise BBRadarClientError("program payload was not a list")

        normalized: list[dict[str, Any]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            normalized.append(item)
        return normalized
