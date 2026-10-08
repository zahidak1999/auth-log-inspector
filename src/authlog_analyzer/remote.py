"""Fetch a log file from a caller-supplied HTTPS endpoint."""

from __future__ import annotations

from urllib.error import URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class RemoteLogError(Exception):
    """A safe, user-facing error while fetching a remote log."""


class HttpsOnlyRedirectHandler(HTTPRedirectHandler):

    def redirect_request(self, request, response, code, message, headers, new_url):
        old_parts = urlsplit(request.full_url)
        new_parts = urlsplit(new_url)
        if new_parts.scheme.lower() != "https":
            raise URLError("refusing redirect to a non-HTTPS URL")
        if new_parts.netloc.lower() != old_parts.netloc.lower():
            raise URLError("refusing redirect to a different server")
        return super().redirect_request(request, response, code, message, headers, new_url)


def safe_url_label(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or "remote server"
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def fetch_remote_log(
    url: str,
    *,
    timeout: float = 10,
    max_bytes: int = 10 * 1024 * 1024,
    bearer_token: str | None = None,
) -> str:
    """Fetch plain-text log contents from an HTTPS endpoint, with bounded size."""
    try:
        parts = urlsplit(url)
        parts.port
    except ValueError as error:
        raise RemoteLogError("remote log URL is invalid") from error
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise RemoteLogError("remote log URLs must use HTTPS and include a hostname")
    if parts.username or parts.password:
        raise RemoteLogError("do not put credentials in the URL; use --token-env instead")
    if timeout <= 0:
        raise RemoteLogError("timeout must be greater than zero")
    if max_bytes < 1:
        raise RemoteLogError("maximum download size must be greater than zero")

    try:
        request = Request(
            url,
            headers={"Accept": "text/plain, application/json, application/x-ndjson"},
        )
        if bearer_token:
            request.add_header("Authorization", f"Bearer {bearer_token}")
        opener = build_opener(HttpsOnlyRedirectHandler())
        with opener.open(request, timeout=timeout) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise RemoteLogError(f"remote log too big, the {max_bytes}-byte download limit")
            content = response.read(max_bytes + 1)
    except RemoteLogError:
        raise
    except (OSError, URLError, ValueError) as error:
        raise RemoteLogError(f"could not fetch remote log ({error})") from error

    if len(content) > max_bytes:
        raise RemoteLogError(f"remote log too big, the {max_bytes}-byte download limit")
    return content.decode("utf-8", errors="replace")
