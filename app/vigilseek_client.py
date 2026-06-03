from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import requests

VIGILSEEK_API_BASE_URL = "https://new-api.vigilseek.com"


class VigilSeekClientError(RuntimeError):
    """Raised when vigilseek data cannot be fetched."""


class VigilSeekClient:
    def __init__(self, base_url: str, timeout_seconds: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_base_url = self._resolve_api_base_url(self.base_url)
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()

    def close(self) -> None:
        self.session.close()

    @staticmethod
    def _resolve_api_base_url(base_url: str) -> str:
        parsed = urlsplit(base_url)
        host = parsed.netloc.casefold()
        if host in {"vigilseek.com", "www.vigilseek.com"}:
            return VIGILSEEK_API_BASE_URL
        return base_url.rstrip("/")

    def fetch_programs(self) -> list[dict[str, Any]]:
        try:
            response = self.session.get(
                f"{self.api_base_url}/w3-bug-bounties",
                params={"order": "DESC", "sort": "startDate"},
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise VigilSeekClientError(f"vigilseek program fetch failed: {exc}") from exc

        if not response.ok:
            raise VigilSeekClientError(
                f"vigilseek program fetch failed with status {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise VigilSeekClientError("vigilseek response was not valid JSON") from exc
        if not isinstance(payload, list):
            raise VigilSeekClientError("vigilseek payload was not a list")

        normalized: list[dict[str, Any]] = []
        for item in payload:
            if isinstance(item, dict):
                normalized.append(item)
        return normalized
