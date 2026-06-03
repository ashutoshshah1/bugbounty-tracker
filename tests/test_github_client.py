from __future__ import annotations

import unittest
from unittest.mock import Mock

from requests.exceptions import ConnectTimeout

from app.github_client import GitHubClient, GitHubClientError


class GitHubClientTest(unittest.TestCase):
    def test_request_wraps_transport_errors(self) -> None:
        client = GitHubClient(timeout_seconds=1, retry_total=0)
        client.session.get = Mock(side_effect=ConnectTimeout("connect timeout=1"))

        with self.assertRaises(GitHubClientError) as ctx:
            client.fetch_authenticated_user()

        self.assertIn("connect timeout", str(ctx.exception))
        self.assertIsNone(ctx.exception.status_code)

        client.close()


if __name__ == "__main__":
    unittest.main()
