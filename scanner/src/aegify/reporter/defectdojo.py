"""DefectDojo reporter - uploads SARIF scan results to DefectDojo."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from aegify.models import ScanResult
from aegify.reporter.sarif import SARIFReporter

logger = logging.getLogger(__name__)


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

        try:
            url = f"{self.base_url}/api/v2/import-scan/"
            req = Request(
                url,
                data=body,
                headers={
                    "Authorization": f"Token {self.api_token}",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
                method="POST",
            )
            with urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                test_id = data.get("test")
                logger.info("Uploaded SARIF to DefectDojo: test=%s", test_id)
                return test_id if isinstance(test_id, int) else None

        except HTTPError as e:
            logger.error(
                "DefectDojo upload failed: HTTP %d - %s",
                e.code,
                e.read().decode("utf-8", errors="replace")[:200],
            )
        except URLError as e:
            logger.error("DefectDojo upload failed: %s", e.reason)
        except Exception:
            logger.exception("DefectDojo upload failed")

        return None

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

        try:
            url = f"{self.base_url}/api/v2/import-scan/"
            req = Request(
                url,
                data=body,
                headers={
                    "Authorization": f"Token {self.api_token}",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
                method="POST",
            )
            with urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                test_id = data.get("test")
                logger.info("Uploaded SARIF file to DefectDojo: test=%s", test_id)
                return test_id if isinstance(test_id, int) else None

        except HTTPError as e:
            logger.error(
                "DefectDojo upload failed: HTTP %d - %s",
                e.code,
                e.read().decode("utf-8", errors="replace")[:200],
            )
        except URLError as e:
            logger.error("DefectDojo upload failed: %s", e.reason)
        except Exception:
            logger.exception("DefectDojo upload failed")

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
