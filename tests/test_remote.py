import io
import unittest
from unittest.mock import patch
from urllib.error import URLError
from urllib.request import Request

from authlog_analyzer.remote import (
    HttpsOnlyRedirectHandler,
    RemoteLogError,
    fetch_remote_log,
    safe_url_label,
)


class FakeResponse(io.BytesIO):
    def __init__(self, content, content_length=None):
        super().__init__(content)
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class RemoteLogTests(unittest.TestCase):
    def test_rejects_non_https_url(self):
        with self.assertRaisesRegex(RemoteLogError, "HTTPS"):
            fetch_remote_log("http://logs.example.test/auth.log")

    def test_rejects_credentials_embedded_in_url(self):
        with self.assertRaisesRegex(RemoteLogError, "credentials in the URL"):
            fetch_remote_log("https://user:secret@logs.example.test/auth.log")

    def test_sends_optional_bearer_token_and_reads_log_text(self):
        log_contents = b"Oct  8 09:14:02 host sshd[1]: Failed password for root from 203.0.113.44 port 22 ssh2\n"
        response = FakeResponse(log_contents, content_length=len(log_contents))
        opener = unittest.mock.Mock()
        opener.open.return_value = response

        with patch("authlog_analyzer.remote.build_opener", return_value=opener):
            result = fetch_remote_log(
                "https://logs.example.test/export/auth.log?view=latest",
                bearer_token="sample-token",
            )

        self.assertEqual(result.encode(), log_contents)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer sample-token")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 10)

    def test_rejects_content_larger_than_limit(self):
        response = FakeResponse(b"12345", content_length=5)
        opener = unittest.mock.Mock()
        opener.open.return_value = response

        with patch("authlog_analyzer.remote.build_opener", return_value=opener):
            with self.assertRaisesRegex(RemoteLogError, "download limit"):
                fetch_remote_log("https://logs.example.test/log", max_bytes=4)

    def test_safe_label_removes_query_and_fragment(self):
        label = safe_url_label("https://logs.example.test/export?token=private#section")
        self.assertEqual(label, "https://logs.example.test/export")

    def test_rejects_redirect_to_a_different_server(self):
        request = Request("https://logs.example.test/log")
        with self.assertRaisesRegex(URLError, "different server"):
            HttpsOnlyRedirectHandler().redirect_request(
                request, None, 302, "Found", {}, "https://other.example.test/log"
            )

    def test_rejects_malformed_url(self):
        with self.assertRaisesRegex(RemoteLogError, "invalid"):
            fetch_remote_log("https://[broken")


if __name__ == "__main__":
    unittest.main()
