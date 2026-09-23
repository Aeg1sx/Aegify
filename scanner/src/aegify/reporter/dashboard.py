"""Authenticated, project-scoped SARIF delivery to a self-hosted dashboard."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_REPORT_BYTES = 100 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024


class DashboardUploadError(ValueError):
    """A bounded diagnostic that never includes credentials or response bodies."""


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        raise DashboardUploadError("Dashboard redirects are rejected; use its exact origin.")


def upload_sarif(
    report: bytes,
    origin: str,
    token: str,
    *,
    project_id: str = "",
    repository: str = "",
    branch: str = "",
    commit: str = "",
) -> dict[str, Any]:
    """Upload once, using HTTPS (or explicit loopback HTTP) without redirects."""
    try:
        url = urlsplit(origin)
        valid_port = url.port is None or 0 < url.port < 65536
    except ValueError as error:
        raise DashboardUploadError("Invalid dashboard origin.") from error
    if (
        not url.hostname
        or not valid_port
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
        or url.path not in ("", "/")
        or any(ord(character) < 33 for character in origin)
        or not (
            url.scheme == "https"
            or (url.scheme == "http" and url.hostname in ("localhost", "127.0.0.1", "::1"))
        )
    ):
        raise DashboardUploadError(
            "Use an HTTPS dashboard origin, or loopback HTTP for a local install."
        )
    if (
        not token
        or len(token) > 512
        or not token.isascii()
        or any(ord(c) <= 32 or ord(c) == 127 for c in token)
    ):
        raise DashboardUploadError("Set AEGIFY_UPLOAD_TOKEN to a project CI credential.")
    if not report or len(report) > MAX_REPORT_BYTES:
        raise DashboardUploadError("SARIF must be non-empty and at most 100 MiB.")
    query = urlencode(
        {
            key: value
            for key, value in {
                "projectId": project_id,
                "repository": repository,
                "branch": branch,
                "commit": commit,
            }.items()
            if value
        }
    )
    request = Request(
        f"{origin.rstrip('/')}/api/upload" + (f"?{query}" if query else ""),
        data=report,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with build_opener(_RejectRedirects()).open(request, timeout=60) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise DashboardUploadError("Dashboard response exceeds the size limit.")
            result: Any = json.loads(data)
    except HTTPError as error:
        raise DashboardUploadError(f"Dashboard rejected the upload (HTTP {error.code}).") from None
    except URLError, TimeoutError, OSError:
        raise DashboardUploadError(
            "Dashboard upload failed; check connectivity and TLS trust."
        ) from None
    except (ValueError, UnicodeError) as error:
        if isinstance(error, DashboardUploadError):
            raise
        raise DashboardUploadError("Dashboard returned an invalid upload receipt.") from None
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("scanId"), str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", result["scanId"])
        or not isinstance(result.get("findingsCount"), int)
        or isinstance(result["findingsCount"], bool)
        or result["findingsCount"] < 0
    ):
        raise DashboardUploadError("Dashboard returned an invalid upload receipt.")
    return result
