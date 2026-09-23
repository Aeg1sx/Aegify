"""Project credential delivery must not leak to redirect destinations or logs."""

from __future__ import annotations

import io
import json
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from urllib.request import Request

import pytest
from typer.testing import CliRunner

from aegify.cli import app
from aegify.reporter.dashboard import DashboardUploadError, _RejectRedirects, upload_sarif


def test_project_receipt_and_bounded_authenticated_request() -> None:
    response = io.BytesIO(json.dumps({"scanId": "synthetic-scan", "findingsCount": 0}).encode())
    opener = MagicMock()
    opener.open.return_value = response
    with patch("aegify.reporter.dashboard.build_opener", return_value=opener):
        receipt = upload_sarif(
            b"{}",
            "https://dashboard.example.test",
            "synthetic-test-token",
            project_id="project-a",
            branch="feature/test",
        )
    assert receipt["scanId"] == "synthetic-scan"
    request = opener.open.call_args.args[0]
    assert request.get_header("Authorization") == "Bearer synthetic-test-token"
    assert "projectId=project-a" in request.full_url
    assert "branch=feature%2Ftest" in request.full_url
    assert "synthetic-test-token" not in request.full_url
    assert opener.open.call_args.kwargs["timeout"] == 60


@pytest.mark.parametrize(
    "origin",
    [
        "http://internal.example.test",
        "https://user:secret@example.test",
        "https://example.test/path",
        "https://example.test?token=secret",
        "https://example.test#fragment",
        "file:///tmp/report",
        "https://example.test:bad",
    ],
)
def test_invalid_origins_never_send_credentials(origin: str) -> None:
    with patch("aegify.reporter.dashboard.build_opener") as opener:
        with pytest.raises(DashboardUploadError):
            upload_sarif(b"{}", origin, "synthetic-test-token")
        opener.assert_not_called()


def test_redirect_rejection_and_redacted_error() -> None:
    with pytest.raises(DashboardUploadError, match="redirects are rejected"):
        _RejectRedirects().redirect_request(
            Request("https://dashboard.example.test"),
            None,
            302,
            "Moved",
            {},
            "https://different.example.test",
        )
    opener = MagicMock()
    opener.open.side_effect = HTTPError(
        "https://dashboard.example.test", 401, "synthetic-test-token", {}, None
    )  # type: ignore[arg-type]
    with patch("aegify.reporter.dashboard.build_opener", return_value=opener):
        with pytest.raises(DashboardUploadError, match="HTTP 401") as error:
            upload_sarif(b"{}", "https://dashboard.example.test", "synthetic-test-token")
    assert "synthetic-test-token" not in str(error.value)


def test_upload_command_fails_closed_without_credentials(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    report = tmp_path / "report.sarif"
    report.write_text('{"runs": []}')
    monkeypatch.delenv("AEGIFY_UPLOAD_TOKEN", raising=False)
    result = CliRunner().invoke(app, ["upload", str(report)])
    assert result.exit_code == 4
    assert "AEGIFY_UPLOAD_TOKEN" in result.output
