"""Parse inert client configurations and exercise the installed rule contracts."""

from pathlib import Path
from textwrap import dedent

import pytest

from aegify.config import AegifyConfig
from aegify.models import EvidenceState, FindingDisposition
from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_tls import tls_settings


def settings(source: str):
    return [
        (fact.api, fact.mode, fact.line) for fact in tls_settings(dedent(source).strip().encode())
    ]


@pytest.mark.parametrize(
    ("imports", "statement", "api", "mode"),
    [
        ("import requests as web", "web.get(url, verify=False)", "requests.get", "http_option"),
        (
            "from requests import post as send",
            "send(url, verify=False)",
            "requests.post",
            "http_option",
        ),
        (
            "import requests",
            "requests.Session().get(url, verify=False)",
            "requests.Session.get",
            "http_option",
        ),
        ("import httpx", "httpx.AsyncClient(verify=False)", "httpx.AsyncClient", "http_option"),
        (
            "import aiohttp",
            "aiohttp.request('GET', url, ssl=False)",
            "aiohttp.request",
            "http_option",
        ),
        (
            "import smtplib as mail",
            "mail.SMTP_SSL(host, port)",
            "smtplib.SMTP_SSL",
            "implicit_context",
        ),
        (
            "from smtplib import SMTP",
            "SMTP().starttls(context=None)",
            "smtplib.SMTP.starttls",
            "implicit_context",
        ),
        (
            "import smtplib, ssl",
            "smtplib.SMTP().starttls(context=ssl._create_unverified_context())",
            "smtplib.SMTP.starttls",
            "unverified_context",
        ),
        (
            "import ssl as tls",
            "tls._create_default_https_context = tls._create_unverified_context",
            "ssl._create_default_https_context",
            "https_default",
        ),
    ],
)
def test_known_api_at_recorded_line(imports, statement, api, mode):
    assert settings(f"{imports}\n{statement}") == [(api, mode, 2)]


@pytest.mark.parametrize(
    "source",
    [
        "import requests\nrequests.get(url, verify=True)",
        "import requests\nrequests.get(url, verify='/etc/example/ca.pem')",
        'import requests\nrequests.get(url, params={"note": "verify=False"})',
        "import requests\ndef download(requests):\n    return requests.get(url, verify=False)",
        "import requests\nrequests.get = fetch\nrequests.get(url, verify=False)",
        "import requests\nrequests.get(url, verify=False, **extra)",
        "import requests\nrequests.get('http://example.test', verify=False)",
        "import httpx\nhttpx.Client().get(url, verify=False)",
        "import aiohttp\naiohttp.ClientSession().get(url, ssl=False, fingerprint=key)",
        "import smtplib, ssl\nsmtplib.SMTP_SSL(host, context=ssl.create_default_context())",
        "import smtplib, ssl\n"
        "smtplib.SMTP_SSL(host, context=ssl.create_default_context(cafile=ca))",
        "import smtplib\nmail = smtplib.SMTP()\nmail.starttls = patched\nmail.starttls()",
        "import smtplib\nsmtplib.SMTP.starttls = patched\nsmtplib.SMTP().starttls()",
        "from aiosmtplib import SMTP\nSMTP().starttls()",
        "import ssl\nssl._create_default_https_context = ssl.create_default_context",
        'import ssl\nsample = "ssl._create_default_https_context = ssl._create_unverified_context"',
    ],
)
def test_verified_dynamic_or_unrelated_call_abstains(source):
    assert settings(source) == []


def test_typed_clients_instance_fields_and_with_as():
    assert settings("""
        from smtplib import SMTP
        import aiohttp
        class Mailer:
            def make(self) -> SMTP:
                return SMTP()
            def connect(self):
                self.transport = self.make()
            def close(self):
                self.transport = None
            def upgrade(self):
                self.transport.starttls()
        async def read(session: aiohttp.ClientSession | None):
            await session.get(url, ssl=False)
        def check():
            with SMTP() as client:
                client.starttls()
    """) == [
        ("smtplib.SMTP.starttls", "implicit_context", 11),
        ("aiohttp.ClientSession.get", "http_option", 13),
        ("smtplib.SMTP.starttls", "implicit_context", 16),
    ]


def test_conflicting_member_and_lexically_rebound_factory_abstain():
    assert (
        settings("""
        import smtplib
        def make() -> smtplib.SMTP:
            return smtplib.SMTP()
        class Mailer:
            def open(self):
                self.client = make()
            def replace(self, client):
                self.client = client
            def send(self):
                self.client.starttls()
        def other(make):
            client = make()
            client.starttls()
    """)
        == []
    )


@pytest.mark.parametrize("handler", ["except OSError:", "except* OSError:"])
def test_client_assignment_reaches_only_the_successful_try_arm(handler):
    result = settings(f"""
        import smtplib
        class Mail:
            def replace(self, other):
                self.client = other
            def connect(self):
                try:
                    self.client = smtplib.SMTP()
                {handler}
                    self.client.starttls()
                else:
                    if self.upgrade:
                        self.client.starttls()
                finally:
                    self.client.starttls()
                self.client.starttls()
    """)
    assert result == [("smtplib.SMTP.starttls", "implicit_context", 12)]


def test_conditional_assignment_inside_try_does_not_cover_else():
    assert not settings("""
        import smtplib
        class Mail:
            def reset(self, previous):
                self.client = previous
            def open(self, use_standard):
                try:
                    if use_standard:
                        self.client = smtplib.SMTP()
                except OSError:
                    return
                else:
                    self.client.starttls()
    """)


def test_cli_engine_rule_ids_remediation_and_repository_shadowing(tmp_path: Path):
    path = tmp_path / "settings.py"
    path.write_text(
        "import smtplib, requests, ssl\nrequests.get(url, verify=False)\n"
        "smtplib.SMTP().starttls(context=ssl._create_unverified_context())\n"
    )
    config = AegifyConfig()
    config.llm.enabled = False
    config.storage.backend = "memory"
    engine = ScanEngine(config=config)
    scan = engine.scan_files(tmp_path, [path])
    assert scan.status == "completed"
    findings = [finding for finding in scan.findings if finding.cwe_id == 295]
    assert {(f.rule_id, f.line_start) for f in findings} == {
        ("AEG-CRYPTO-003", 2),
        ("AEG-A02-005", 2),
        ("AEG-A02-005", 3),
    }
    assert all(f.evidence_state == EvidenceState.CANDIDATE for f in findings)
    assert all(f.disposition == FindingDisposition.ADVISORY and f.remediation for f in findings)
    shadowed = [tmp_path / "requests.py", tmp_path / "ssl.py"]
    for module in shadowed:
        module.write_text("pass\n")
    scan = engine.scan_files(tmp_path, [path, *shadowed])
    assert scan.status == "completed"
    assert not any(f.cwe_id == 295 for f in scan.findings)
