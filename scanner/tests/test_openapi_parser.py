"""Tests for OpenAPI discovery boundaries."""

from aegify.scanner.openapi_parser import find_openapi_files


def test_find_openapi_files_requires_schema_marker_and_skips_dependencies(tmp_path):
    valid = tmp_path / "service" / "api.yml"
    rule = tmp_path / "rules" / "api.yml"
    dependency = tmp_path / "scanner" / ".venv" / "openapi.yaml"
    valid.parent.mkdir(parents=True)
    rule.parent.mkdir(parents=True)
    dependency.parent.mkdir(parents=True)
    valid.write_text("openapi: 3.1.0\npaths: {}\n")
    rule.write_text("id: AEG-API-001\npatterns: []\n")
    dependency.write_text("openapi: 3.1.0\npaths: {}\n")

    assert find_openapi_files(tmp_path) == [valid]
