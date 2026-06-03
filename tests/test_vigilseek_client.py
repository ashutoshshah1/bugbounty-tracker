from __future__ import annotations

import unittest
from unittest.mock import Mock

from app.vigilseek_client import VIGILSEEK_API_BASE_URL, VigilSeekClient


class VigilSeekClientTest(unittest.TestCase):
    def test_public_bug_bounty_url_resolves_to_backing_api(self) -> None:
        client = VigilSeekClient("https://www.vigilseek.com/bug-bounty", timeout_seconds=1)
        response = Mock()
        response.ok = True
        response.json.return_value = [{"id": "w3bb-HackenProof-example"}]
        client.session.get = Mock(return_value=response)

        try:
            programs = client.fetch_programs()
        finally:
            client.close()

        self.assertEqual(programs, [{"id": "w3bb-HackenProof-example"}])
        client.session.get.assert_called_once_with(
            f"{VIGILSEEK_API_BASE_URL}/w3-bug-bounties",
            params={"order": "DESC", "sort": "startDate"},
            timeout=1,
        )

    def test_direct_api_url_is_still_supported(self) -> None:
        client = VigilSeekClient("https://new-api.vigilseek.com")
        try:
            self.assertEqual(client.api_base_url, "https://new-api.vigilseek.com")
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
