"""Explicit HTTPS transport with bounded bodies and no redirects."""

from __future__ import annotations

import urllib.request
from urllib.parse import urlsplit

from .io_utils import read_bounded


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # In particular, never forward API authorization to a redirected host.
        return None


def validate_url(url: str, *, local_http: bool = False) -> str:
    if not isinstance(url, str) or any(ord(char) <= 32 or ord(char) == 127 for char in url):
        raise ValueError("URL contains whitespace or control characters")
    parsed = urlsplit(url)
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("URL requires a host and must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("URL must not contain a query or fragment")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid URL port")
    loopback = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (local_http and parsed.scheme == "http" and loopback):
        raise ValueError("HTTPS required; HTTP is allowed only for an explicit loopback model endpoint")
    return url


def request_bytes(request: urllib.request.Request, *, limit: int, timeout: int,
                  local_http: bool = False) -> bytes:
    validate_url(request.full_url, local_http=local_http)
    opener = urllib.request.build_opener(NoRedirect())
    # Schemes are validated above and redirects are disabled by this opener.
    with opener.open(request, timeout=timeout) as response:  # nosec B310
        return read_bounded(response, limit)


def download(url: str, *, limit: int) -> bytes:
    request = urllib.request.Request(validate_url(url), headers={"User-Agent": "corpusshield-ot-research"})
    return request_bytes(request, limit=limit, timeout=120)
