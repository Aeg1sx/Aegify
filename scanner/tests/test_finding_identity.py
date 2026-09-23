import json
from pathlib import Path

from aegify.identity import finding_fingerprint_v2, relative_identity_path
from aegify.models import EvidenceProvenance, Finding, ScanResult, Severity
from aegify.reporter.sarif import SARIFReporter


def test_shared_identity_vectors_match_the_python_contract() -> None:
    fixture = (
        Path(__file__).resolve().parents[2]
        / "dashboard/src/lib/fixtures/finding-identities-v2.json"
    )
    for vector in json.loads(fixture.read_text()):
        data = vector["input"]
        assert (
            finding_fingerprint_v2(
                data["ruleId"],
                data.get("repositoryId", ""),
                data.get("modulePath", ""),
                data["filePath"],
                data.get("codeSnippet") or data["message"],
            )
            == vector["sha256"]
        )


def test_finding_v2_survives_checkout_changes_but_v1_is_retained_for_compatibility() -> None:
    finding = Finding(
        rule_id="AEG-IDENTITY",
        rule_name="Identity control",
        severity=Severity.LOW,
        confidence=0.5,
        file_path="/old/src/app.py",
        line_start=10,
        line_end=10,
        code_snippet="review(value)",
        provenance=EvidenceProvenance(repository_id="service", module_path="src/app.py"),
    )
    moved = finding.model_copy(
        update={"file_path": "/new/src/app.py", "line_start": 20, "line_end": 20}
    )
    assert finding.fingerprint == moved.fingerprint
    assert finding.legacy_fingerprint != moved.legacy_fingerprint
    separate = finding.model_copy(
        update={"provenance": EvidenceProvenance(repository_id="other", module_path="src/app.py")}
    )
    assert separate.fingerprint != finding.fingerprint
    result = SARIFReporter().generate(ScanResult(findings=[finding]))["runs"][0]["results"][0]
    assert result["partialFingerprints"] == {
        "aegifyFingerprint/v2": finding.fingerprint,
        "aegifyFingerprint/v1": finding.legacy_fingerprint,
    }


def test_invalid_logical_paths_do_not_collapse_into_an_admitted_module() -> None:
    for value in ("../app.py", "/root/app.py", "C:\\root\\app.py", "src/../../app.py"):
        assert relative_identity_path(value) == ""
    assert relative_identity_path("./src\\app.py") == "src/app.py"
