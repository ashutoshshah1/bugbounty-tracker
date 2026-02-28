from __future__ import annotations

from typing import Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class TelegramNotifier:
    def __init__(self, bot_token: str | None, chat_id: str | None, timeout_seconds: int = 30) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.7,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods={"POST"},
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)

    @property
    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def close(self) -> None:
        self.session.close()

    def send_message(self, text: str) -> bool:
        if not self.enabled:
            return False

        sent = False
        for chunk in self._chunk_message(text):
            response = self.session.post(
                f"https://api.telegram.org/bot{self.bot_token}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": chunk,
                    "disable_web_page_preview": True,
                },
                timeout=self.timeout_seconds,
            )
            if not response.ok:
                raise RuntimeError(
                    f"telegram send failed with status {response.status_code}: {response.text[:180]}"
                )
            sent = True
        return sent

    @staticmethod
    def _chunk_message(text: str, max_chars: int = 4000) -> Iterable[str]:
        current = ""
        for line in text.splitlines():
            candidate = f"{current}\n{line}" if current else line
            if len(candidate) <= max_chars:
                current = candidate
                continue
            if current:
                yield current
            current = line

        if current:
            yield current
