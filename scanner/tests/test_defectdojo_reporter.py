"""Tests for the DefectDojo reporter."""

import json
from unittest.mock import MagicMock, patch

from aegify.models import (
    Finding,
    ScanResult,
    ScanStatus,
    Severity,
)
from aegify.reporter.defectdojo import DefectDojoReporter


class TestDefectDojoReporter:
    def test_build_multipart_body(self):
        body = DefectDojoReporter._build_multipart_body(
            boundary="testboundary",
            fields={"scan_type": "SARIF", "engagement": "1"},
            file_field="file",
            file_name="results.sarif",
            file_content=b'{"version": "2.1.0"}',
        )

        assert b"testboundary" in body
        assert b"scan_type" in body
        assert b"SARIF" in body
        assert b"results.sarif" in body
        assert b'{"version": "2.1.0"}' in body

    def test_build_multipart_body_skips_empty_fields(self):
        body = DefectDojoReporter._build_multipart_body(
            boundary="testboundary",
            fields={"scan_type": "SARIF", "product_name": ""},
            file_field="file",
            file_name="results.sarif",
            file_content=b"{}",
        )

        assert b"product_name" not in body

    @patch("aegify.reporter.defectdojo.urlopen")
    def test_upload_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"test": 42}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        reporter = DefectDojoReporter("http://localhost:8080", "test-token")
        scan_result = ScanResult(
            status=ScanStatus.COMPLETED,
            findings=[
                Finding(
                    rule_id="AEG-SQL-001",
                    rule_name="SQL Injection",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    file_path="app.py",
                    line_start=10,
                    line_end=10,
                    message="Test finding",
                )
            ],
            files_scanned=5,
        )

        test_id = reporter.upload(scan_result, engagement_id=1)
        assert test_id == 42
        mock_urlopen.assert_called_once()

        # Verify the request was multipart with SARIF
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert request.get_header("Authorization") == "Token test-token"
        assert "multipart/form-data" in request.get_header("Content-type")
        assert request.get_method() == "POST"
        assert request.full_url == "http://localhost:8080/api/v2/import-scan/"

    @patch("aegify.reporter.defectdojo.urlopen")
    def test_upload_failure_returns_none(self, mock_urlopen):
        from urllib.error import HTTPError

        mock_urlopen.side_effect = HTTPError(
            url="http://localhost:8080/api/v2/import-scan/",
            code=500,
            msg="Internal Server Error",
            hdrs=None,
            fp=MagicMock(read=MagicMock(return_value=b"error")),
        )

        reporter = DefectDojoReporter("http://localhost:8080", "token")
        scan_result = ScanResult(status=ScanStatus.COMPLETED)

        result = reporter.upload(scan_result)
        assert result is None
