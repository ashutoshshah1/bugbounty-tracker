from __future__ import annotations

import unittest

from app.service import TrackerService


class SecretMaskingTest(unittest.TestCase):
    def test_masks_telegram_bot_tokens_inside_api_urls(self) -> None:
        raw_token = "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ_123456"
        text = f"https://api.telegram.org/bot{raw_token}/sendMessage"

        masked = TrackerService._mask_secrets(text)

        self.assertNotIn(raw_token, masked)
        self.assertIn("https://api.telegram.org/bot***:***/sendMessage", masked)

    def test_masks_raw_github_and_telegram_tokens(self) -> None:
        masked = TrackerService._mask_secrets(
            "github_pat_abcdef ghp_abcdef123456 1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ_123456"
        )

        self.assertNotIn("github_pat_abcdef", masked)
        self.assertNotIn("ghp_abcdef123456", masked)
        self.assertNotIn("1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ_123456", masked)


if __name__ == "__main__":
    unittest.main()
