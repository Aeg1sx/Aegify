"""Source-only controls for unescaped HTML template environments."""

from textwrap import dedent, indent

import pytest

from aegify.config import AegifyConfig
from aegify.models import EvidenceState, FindingDisposition
from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_jinja import environments

IMPORTS = "from jinja2 import Environment as Engine, FileSystemLoader as Loader\n"


def _settings(body, parameter="options=None", base="Application"):
    return (
        IMPORTS + "from tornado.web import Application\n"
        f"class Pages({base}):\n    def settings(self, {parameter}):\n"
        + indent(dedent(body).strip(), "        ")
        + "\n"
    )


@pytest.mark.parametrize(
    "body, use, optional",
    [
        (
            "env = Engine(loader=Loader('.'))\nreturn env.get_template('page.html')",
            "html_template",
            False,
        ),
        (
            "env = Engine(autoescape=False, loader=Loader('.'))\n"
            "return env.get_template(name='page.xhtml')",
            "html_template",
            False,
        ),
        (
            "kw = options or {}\nenv = Engine(loader=Loader('.'), **kw)\n"
            "return dict(jinja_env=env)",
            "web_settings",
            True,
        ),
        (
            "kw = options if options else {}\nenv = Engine(loader=Loader('.'), **kw)\n"
            "settings = {'jinja2_env': env}\nreturn settings",
            "web_settings",
            True,
        ),
    ],
)
def test_environment_default_and_use(body, use, optional):
    source = _settings(body)
    facts = environments(source.encode())
    assert [(fact.use, fact.optional_options) for fact in facts] == [(use, optional)]
    assert "env = Engine" in source.splitlines()[facts[0].line - 1]
    assert "env" in source.splitlines()[facts[0].use_line - 1]


@pytest.mark.parametrize(
    "body",
    [
        "env = Engine(loader=Loader('.'))\nreturn env.get_template('email.txt')",
        "env = Engine(loader=Loader('.'))\nreturn env.get_template(template_name)",
        "env = Engine(loader=Loader('.'))\nconfigure(env)\nreturn dict(jinja_env=env)",
        "env = Engine(loader=Loader('.'))\nenv.autoescape = True\nreturn dict(jinja_env=env)",
        "env = Engine(loader=Loader('.'), autoescape=select_autoescape())\n"
        "return dict(jinja_env=env)",
        "env = Engine(loader=Loader('.'), **options)\nreturn dict(jinja_env=env)",
        "kw = options or {}\nkw.update(default_options)\n"
        "env = Engine(loader=Loader('.'), **kw)\nreturn dict(jinja_env=env)",
        "kw = {'autoescape': True}\nkw.update(options or {})\n"
        "env = Engine(loader=Loader('.'), **kw)\nreturn dict(jinja_env=env)",
        "if not options: return {}\nkw = options or {}\n"
        "env = Engine(loader=Loader('.'), **kw)\nreturn dict(jinja_env=env)",
        "env = Engine(loader=Loader('.'))\nreturn {'jinja_env': env, 'jinja_env': patched}",
        "env = Engine(loader=Loader('.'))\nreturn {'jinja_env': env, **extra}",
        "env = Engine(loader=custom_loader)\nreturn dict(jinja_env=env)",
        "env = Engine(loader=Loader('.'))\nother = dict(jinja_env=env)\nreturn {}",
        "env = Engine(loader=Loader('.'))\ndict = custom\nreturn dict(jinja_env=env)",
        "Engine = LocalEnv\nenv = Engine(loader=Loader('.'))\nreturn dict(jinja_env=env)",
        "env = Engine(loader=Loader('.'))\nenv = alternate\nreturn dict(jinja_env=env)",
    ],
)
def test_ambiguous_or_protected_environment(body):
    assert not environments(_settings(body).encode())


def test_web_binding_and_optional_parameters_must_be_proven():
    source = (
        "kw = options or {}\nenv = Engine(loader=Loader('.'), **kw)\nreturn dict(jinja_env=env)"
    )
    assert not environments(_settings(source, base="Unrelated").encode())
    assert not environments(_settings(source, parameter="options").encode())


@pytest.mark.parametrize("shadow", ["", "jinja2", "tornado"])
def test_packaged_rule_advises_at_constructor_only_with_external_bindings(tmp_path, shadow):
    source = "env = Engine(loader=Loader('.'))\nreturn dict(jinja_env=env)"
    page = tmp_path / "pages.py"
    page.write_text(_settings(source))
    if shadow:
        (tmp_path / f"{shadow}.py").write_text("class StandIn: pass\n")
    engine = ScanEngine(
        AegifyConfig.model_validate(
            {
                "llm": {"enabled": False},
                "storage": {"backend": "memory"},
                "rules": {"severity_threshold": "low"},
            }
        )
    )
    result = engine.scan_files(tmp_path, sorted(tmp_path.glob("*.py")))
    hits = [f for f in result.findings if f.rule_id == "AEG-XSS-005"]
    if shadow:
        assert not hits
    else:
        assert [(f.line_start, f.evidence_state, f.disposition) for f in hits] == [
            (5, EvidenceState.CANDIDATE, FindingDisposition.ADVISORY)
        ]
        assert "line 6" in hits[0].message
