"""DefectDojo reporter - uploads SARIF scan results to DefectDojo."""

from __future__ import annotations

import json
import logging
from http.client import HTTPException
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from aegify.models import ScanResult
from aegify.reporter.sarif import SARIFReporter

logger = logging.getLogger(__name__)


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


class DefectDojoReporter:
    """Reports scan results to DefectDojo via its SARIF import API."""

    def __init__(self, base_url: str, api_token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self._sarif_reporter = SARIFReporter()

    def upload(
        self,
        scan_result: ScanResult,
        engagement_id: int = 1,
        product_name: str | None = None,
    ) -> int | None:
        """Upload scan results as SARIF to DefectDojo.

        Returns the test ID from DefectDojo, or None on failure.
        """
        sarif_data = self._sarif_reporter.generate(scan_result)
        sarif_bytes = json.dumps(sarif_data, indent=2).encode("utf-8")

        boundary = "----AegifyBoundary7MA4YWxkTrZu0gW"
        body = self._build_multipart_body(
            boundary=boundary,
            fields={
                "scan_type": "SARIF",
                "engagement": str(engagement_id),
                "active": "true",
                "verified": "false",
                "scan_date": (
                    scan_result.created_at.strftime("%Y-%m-%d") if scan_result.created_at else ""
                ),
                "product_name": product_name or scan_result.repository or "",
            },
            file_field="file",
            file_name="results.sarif",
            file_content=sarif_bytes,
        )

        return self._post_import(body, boundary)

    def upload_sarif_file(
        self,
        sarif_path: Path,
        engagement_id: int = 1,
    ) -> int | None:
        """Upload an existing SARIF file to DefectDojo."""
        sarif_bytes = sarif_path.read_bytes()

        boundary = "----AegifyBoundary7MA4YWxkTrZu0gW"
        body = self._build_multipart_body(
            boundary=boundary,
            fields={
                "scan_type": "SARIF",
                "engagement": str(engagement_id),
                "active": "true",
                "verified": "false",
            },
            file_field="file",
            file_name=sarif_path.name,
            file_content=sarif_bytes,
        )

        return self._post_import(body, boundary)

    def _post_import(self, body: bytes, boundary: str) -> int | None:
        try:
            url = urlsplit(self.base_url)
            valid_port = url.port is None or 0 < url.port < 65536
        except ValueError:
            logger.error("Invalid DefectDojo URL")
            return None
        if (
            not url.hostname
            or not valid_port
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or "\\" in self.base_url
            or any(ord(c) < 33 or ord(c) == 127 for c in self.base_url)
        ):
            logger.error("Invalid DefectDojo URL")
            return None

        # Match the actual HTTP authority, including brackets around IPv6.
        authority = url.netloc.lower()
        if url.port is not None:
            authority = authority.rpartition(":")[0]
        local_http = url.scheme == "http" and authority in ("localhost", "127.0.0.1", "[::1]")
        if url.scheme != "https" and not local_http:
            logger.error("DefectDojo requires HTTPS, or loopback HTTP for a local install")
            return None

        try:
            opener = (
                build_opener(_RejectRedirects(), ProxyHandler({}))
                if local_http
                else build_opener(_RejectRedirects())
            )
            req = Request(
                f"{self.base_url}/api/v2/import-scan/",
                data=body,
                headers={
                    "Authorization": f"Token {self.api_token}",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
                method="POST",
            )
            with opener.open(req, timeout=60) as resp:
                data = json.load(resp)
            test_id = data.get("test") if isinstance(data, dict) else None
            if type(test_id) is int:
                logger.info("Uploaded SARIF to DefectDojo: test=%d", test_id)
                return test_id
        except HTTPError as error:
            logger.error("DefectDojo upload failed: HTTP %d", error.code)
            error.close()
        except HTTPException, URLError, OSError, ValueError:
            logger.error("DefectDojo upload failed; check the endpoint and its TLS configuration")
        return None

    @staticmethod
    def _build_multipart_body(
        boundary: str,
        fields: dict[str, str],
        file_field: str,
        file_name: str,
        file_content: bytes,
    ) -> bytes:
        """Build a multipart/form-data body for the upload."""
        parts: list[bytes] = []

        for key, value in fields.items():
            if not value:
                continue
            parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
                f"{value}\r\n".encode()
            )

        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{file_field}"; filename="{file_name}"\r\n'
            f"Content-Type: application/json\r\n\r\n".encode()
        )
        parts.append(file_content)
        parts.append(f"\r\n--{boundary}--\r\n".encode())

        return b"".join(parts)
