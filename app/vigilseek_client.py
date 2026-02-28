from __future__ import annotations

from typing import Any

import requests


class VigilSeekClientError(RuntimeError):
    """Raised when vigilseek data cannot be fetched."""


class VigilSeekClient:
    def __init__(self, base_url: str, timeout_seconds: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()

    def close(self) -> None:
        self.session.close()

    def fetch_programs(self) -> list[dict[str, Any]]:
        response = self.session.get(
            f"{self.base_url}/w3-bug-bounties",
            params={"order": "DESC", "sort": "startDate"},
            timeout=self.timeout_seconds,
        )
        if not response.ok:
            raise VigilSeekClientError(
                f"vigilseek program fetch failed with status {response.status_code}"
            )

        payload = response.json()
        if not isinstance(payload, list):
            raise VigilSeekClientError("vigilseek payload was not a list")

        normalized: list[dict[str, Any]] = []
        for item in payload:
            if isinstance(item, dict):
                normalized.append(item)
        return normalized
