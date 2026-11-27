"""Cloudflare configuration evidence through the ordinary scanner and PR interfaces."""

import json
from pathlib import Path

import pytest

from aegify.config import AegifyConfig
from aegify.llm.sources import SourceCatalog
from aegify.models import Language, ScanStatus
from aegify.reporter.sarif import SARIFReporter
from aegify.scanner.ast_parser import ASTParser, detect_language
from aegify.scanner.diff_resolver import DiffResolver
from aegify.scanner.engine import ScanEngine

CANARY = "owned-fixture-value-6931"


def test_worker_preview_compares_the_target_worker_and_retains_only_source_locations(
    tmp_path: Path,
) -> None:
    path = tmp_path / "wrangler.toml"
    queue = "owned-branch-queue"
    path.write_text(
        f'[previews.vars]\nSIGNING_KEY = "{CANARY}"\n'
        f'[[previews.queues.producers]]\nbinding = "BRANCH"\nqueue = "{queue}"\n'
        f'[[env.stage.queues.producers]]\nbinding = "WORKER"\nqueue = "{queue}"\n'
        f'[[env.isolated.queues.producers]]\nbinding = "WORKER"\nqueue = "{queue}"\n'
        "[env.isolated.previews]\n"
        f'[[env.other.previews.queues.producers]]\nbinding = "OTHER"\nqueue = "{queue}"\n'
    )
    engine = ScanEngine(capture_ai_source=True)
    scan = engine.scan(path)
    assert scan.status == ScanStatus.COMPLETED
    assert [(f.rule_id, f.line_start, f.code_snippet) for f in scan.findings] == [
        ("AEG-CF-001", 2, "default.previews.vars.SIGNING_KEY = [withheld]"),
        (
            "AEG-CF-004",
            5,
            "default.previews.queues.producers[0].queue (line 5) "
            "matches env.stage.queues.producers[0].queue (line 8)",
        ),
    ]
    assert all(
        f.provenance.fidelity == "parsed-settings" and not f.blocks_ci for f in scan.findings
    )
    for raw in [scan.model_dump_json(), json.dumps(SARIFReporter().generate(scan))]:
        assert CANARY not in raw and queue not in raw
    assert engine.source_catalog is not None and not engine.source_catalog.files


@pytest.mark.parametrize("name", ["wrangler.json", "wrangler.jsonc"])
def test_nested_worker_preview_source_lines_and_local_selectors(tmp_path: Path, name: str) -> None:
    path = tmp_path / name
    primary = "11111111-1111-4111-8111-111111111111"
    local = "22222222-2222-4222-8222-222222222222"

    def database(binding: str, target: str, dev: str) -> dict[str, object]:
        return {
            "binding": binding,
            "database_id": target,
            "preview_database_id": dev,
            "remote": False,
        }

    section = {
        "d1_databases": [database("DEPLOY", primary, local)],
        "previews": {
            "d1_databases": [
                database("ONLY_DEV", local, primary),
                database("BRANCH", primary, local),
            ],
            "vars": {"API_TOKEN": CANARY, "PUBLIC_API_KEY": CANARY, "PASSWORD": "${PASSWORD}"},
        },
    }
    content = json.dumps({"env": {"blue": section}}, indent=2)
    if name.endswith("jsonc"):
        content = "// Worker settings\n" + content
    path.write_text(content)
    lines = content.splitlines()
    first, second = [i for i, row in enumerate(lines, 1) if f'"database_id": "{primary}"' in row]
    scan = ScanEngine().scan(path)
    bindings = [f for f in scan.findings if f.rule_id == "AEG-CF-001"]
    assert (
        len(bindings) == 1
        and bindings[0].code_snippet == "env.blue.previews.vars.API_TOKEN = [withheld]"
    )
    (shared,) = [f for f in scan.findings if f.rule_id == "AEG-CF-004"]
    assert shared.line_start == second and shared.code_snippet == (
        f"env.blue.previews.d1_databases[1].database_id (line {second}) "
        f"matches env.blue.d1_databases[0].database_id (line {first})"
    )
    path.write_text(json.dumps({"pages_build_output_dir": "./dist", "env": {"preview": section}}))
    assert not ScanEngine().scan(path).findings


@pytest.mark.parametrize(
    ("name", "source", "binding_line", "route_line"),
    [
        (
            "wrangler.toml",
            'workers_dev = false\n[env."staging.blue"]\npreview_urls = true\n'
            'vars = { DATABASE_PASSWORD = "VALUE" }\n',
            4,
            3,
        ),
        (
            "wrangler.json",
            '{\n"workers_dev":false,\n"env":{"staging.blue":{\n"preview_urls":true,'
            '\n"vars":{"DATABASE_PASSWORD":"VALUE"}}}}\n',
            5,
            4,
        ),
        (
            "wrangler.jsonc",
            '\ufeff// deployment\n{\n"workers_dev": false,\n"env":{"staging.blue":{\n'
            '/* credentials */ "vars":{"DATABASE_PASSWORD":"VALUE",},\n"preview_urls":true,},},}\n',
            5,
            6,
        ),
    ],
)
def test_scan_retains_only_named_configuration_facts(
    tmp_path: Path,
    name: str,
    source: str,
    binding_line: int,
    route_line: int,
) -> None:
    path = tmp_path / name
    path.write_text(source.replace("VALUE", CANARY))
    config = AegifyConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config, capture_ai_source=True)
    scan = engine.scan(tmp_path)
    assert scan.status == ScanStatus.COMPLETED and scan.files_scanned == 1
    assert set(scan.evaluated_rules) == {"AEG-CF-001", "AEG-CF-002", "AEG-CF-003", "AEG-CF-004"}
    assert [(f.rule_id, f.line_start) for f in scan.findings] == [
        ("AEG-CF-001", binding_line),
        ("AEG-CF-002", route_line),
    ]
    for finding in scan.findings:
        assert not finding.blocks_ci
        assert finding.code_snippet_start_line == finding.line_start == finding.line_end
        assert finding.provenance.fidelity == "parsed-settings"
        assert finding.provenance.analysis_kind == "configuration"
        assert finding.provenance.module_path == name
        assert "env.staging.blue" in finding.code_snippet
        assert finding.remediation
    assert scan.analyzed_sources[0].language == Language.WRANGLER
    assert CANARY not in scan.model_dump_json()
    assert CANARY not in json.dumps(engine.storage.load_index(str(tmp_path)))
    assert CANARY not in json.dumps(SARIFReporter().generate(scan))
    for catalog in [engine.source_catalog, SourceCatalog.from_scan(scan, {"local": tmp_path})]:
        assert catalog is not None and not catalog.files
        assert catalog.gap_counts["configuration_values_withheld"] == 1
    changed = DiffResolver(tmp_path).get_changed_files(explicit_files=[name])
    pr_scan = engine.scan_files(tmp_path, changed)
    assert [(f.rule_id, f.line_start) for f in pr_scan.findings] == [
        (f.rule_id, f.line_start) for f in scan.findings
    ]
    path.write_text(source.replace("VALUE", "<placeholder>").replace("true", "false"))
    clean = engine.scan(tmp_path)
    assert clean.status == ScanStatus.COMPLETED and not clean.findings
    assert scan.workspace_snapshot != clean.workspace_snapshot


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (
            "wrangler.toml",
            "workers_dev = false\n[env.staging]\npreview_urls = false\n"
            '[vars]\nAPI_TOKEN = "\u0024{TOKEN}"\nNEXT_PUBLIC_API_KEY = "publishable"\n'
            'API_TOKEN_TTL = "1h"\n[secrets]\nrequired = ["ADMIN_TOKEN"]',
        ),
        (
            "wrangler.jsonc",
            '{"secrets":{"required":["DATABASE_PASSWORD"]},'
            '"workers_dev":false,"vars":{"NOTE":"\\"preview_urls\\":true",'
            '"PUBLIC_API_KEY":"public"},'
            '"env":{"a":{"vars":{"PASSWORD":""}}}}',
        ),
        (
            "wrangler.toml",
            '# preview_urls = true\nmessage = """\n[vars]\nAPI_TOKEN="value"\n"""\n'
            '[[rules]]\ntype = "Text"\n[[rules.vars]]\nAPI_TOKEN = "elsewhere"',
        ),
        (
            "wrangler.json",
            '{"binding":{"vars":{"API_TOKEN":"elsewhere"}},'
            '"env":{"a":{"workers_dev":false},"b":{"preview_urls":true}}}',
        ),
        ("wrangler.json", '{"workers_dev":false,"env":{"prod":{"name":"example"}}}'),
        ("wrangler.json", '{"routes":[{"pattern":"example.test/*"}],"preview_urls":true}'),
        (
            "wrangler.toml",
            'pages_build_output_dir = "./dist"\nworkers_dev=false\npreview_urls=true',
        ),
    ],
)
def test_safe_unresolved_and_out_of_scope_settings(tmp_path: Path, name: str, source: str) -> None:
    path = tmp_path / name
    path.write_text(source)
    ast = ASTParser().parse_file(path)
    assert ast is not None and ast.parse_error_count == 0 and not ast.wrangler_settings


@pytest.mark.parametrize(
    ("name", "source"),
    [
        ("wrangler.jsonc", '{"vars":{"API_TOKEN":"one","API_TOKEN":"two"}}'),
        ("wrangler.json", '{"preview_urls":true, "workers_dev": false, "bad": call()}'),
        ("wrangler.json", '{"vars": null}'),
        ("wrangler.json", '{"env": [false]}'),
        ("wrangler.json", '{"env": {"staging": false}}'),
        ("wrangler.json", '{"previews":null}'),
        ("wrangler.json", '{"previews":{"queues":{"producers":"bad"}}}'),
        ("wrangler.json", '{"previews":{"vars":{"SIGNING_KEY":"fixture"},"kv_namespaces":[7]}}'),
        ("wrangler.json", '{"vars":{"API_TOKEN":"value"},"preview_urls":"false"}'),
        ("wrangler.jsonc", '{"vars":{"API_TOKEN":"value"}, "invalid":[1,,2]}'),
        ("wrangler.toml", '[vars]\nAPI_TOKEN="one"\nAPI_TOKEN="two"'),
        ("wrangler.toml", "workers_dev=false\n[env.qa\npreview_urls=true"),
    ],
)
def test_invalid_manifest_reports_a_gap_without_partial_assignments(
    tmp_path: Path,
    name: str,
    source: str,
) -> None:
    path = tmp_path / name
    path.write_text(source)
    scan = ScanEngine().scan(path)
    assert scan.status == ScanStatus.PARTIAL and not scan.findings
    assert [g.code for g in scan.analysis_gaps] == ["syntax_recovery"]
    assert scan.parse_diagnostics[0].line_start >= 1


def test_grouped_bindings_and_inheritable_switches(tmp_path: Path) -> None:
    path = tmp_path / "wrangler.toml"
    path.write_text(
        'preview_urls = true\nvars = { ACCESS_TOKEN="value", API_KEY="value" }\n'
        "[env.staging]\nworkers_dev=false\n[env.prod]\nworkers_dev = true\n"
        '[env.prod.vars]\n"API_\\u0054OKEN" = """owned\nfixture"""\n'
    )
    scan = ScanEngine().scan(path)
    assert scan.status == ScanStatus.COMPLETED
    bindings = [f for f in scan.findings if f.rule_id == "AEG-CF-001"]
    assert [(f.line_start, f.code_snippet) for f in bindings] == [
        (2, "default.vars.ACCESS_TOKEN = [withheld] · default.vars.API_KEY = [withheld]"),
        (8, "env.prod.vars.API_TOKEN = [withheld]"),
    ]
    (route,) = [f for f in scan.findings if f.rule_id == "AEG-CF-002"]
    assert route.line_start == 4 and "preview_urls = true (line 1)" in route.code_snippet


def test_configuration_identity_disabling_and_file_size(tmp_path: Path) -> None:
    path = tmp_path / "wrangler.jsonc"
    path.write_text('{"workers_dev":false,"preview_urls":true}')
    assert detect_language(tmp_path / "app.jsonc") is None
    assert detect_language(tmp_path / "pyproject.toml") is None
    cfg = AegifyConfig()
    cfg.rules.disabled_rules = ["AEG-CF-002"]
    scan = ScanEngine(cfg).scan(path)
    assert scan.files_scanned == 1 and not scan.findings
    assert "AEG-CF-002" not in scan.evaluated_rules
    cfg.scan.max_file_size_kb = 1
    path.write_text(" " * 1024 + path.read_text())
    assert "source_size_limit" in [g.code for g in ScanEngine(cfg).scan(path).analysis_gaps]


def test_pages_plaintext_variables_and_worker_only_settings(tmp_path: Path) -> None:
    path = tmp_path / "wrangler.toml"
    path.write_text(
        'pages_build_output_dir="./dist"\nworkers_dev=false\npreview_urls=true\n'
        '[env.preview.vars]\nAPI_TOKEN="owned-configuration-marker"\n'
    )
    scan = ScanEngine().scan(path)
    assert [(f.rule_id, f.line_start) for f in scan.findings] == [("AEG-CF-001", 5)]


@pytest.mark.parametrize(
    ("keys", "eligible"),
    [
        ({"exports": {"Archive": {"type": "durable-object", "storage": "sqlite"}}}, False),
        ({"exports": {"Archive": {"type": "durable-object", "state": "deleted"}}}, True),
        ({"durable_objects": {"bindings": [{"name": "ARCHIVE", "class_name": "Archive"}]}}, False),
        (
            {
                "durable_objects": {
                    "bindings": [
                        {"name": "ARCHIVE", "class_name": "Archive", "script_name": "external"}
                    ]
                }
            },
            True,
        ),
    ],
)
def test_version_url_eligibility_is_distinct_from_external_object_bindings(
    tmp_path: Path,
    keys: dict,
    eligible: bool,
) -> None:
    path = tmp_path / "wrangler.json"
    path.write_text(json.dumps({"workers_dev": False, "preview_urls": True, **keys}))
    ast = ASTParser().parse_file(path)
    assert ast and ast.parse_error_count == 0
    assert bool(ast.wrangler_settings) == eligible


def test_routing_inheritance_respects_deployable_environment(tmp_path: Path) -> None:
    path = tmp_path / "wrangler.jsonc"
    path.write_text(
        '{"workers_dev":false,"preview_urls":true,'
        '"exports":{"Archive":{"type":"durable-object","storage":"sqlite"}},'
        '"env":{"staging":{}, "public":{"exports":{}}}}'
    )
    scan = ScanEngine().scan(path)
    (route,) = scan.findings
    assert route.code_snippet.startswith("env.public:")


def test_mixed_workspace_and_pr_selection_bind_qualified_manifest_paths(tmp_path: Path) -> None:
    a, b = tmp_path / "alpha", tmp_path / "bravo"
    a.mkdir()
    b.mkdir()
    for repo in (a, b):
        (repo / "wrangler.toml").write_text("workers_dev=false\npreview_urls=true\n")
    (b / "source.py").write_text("value = 1\n")
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "name: cloud\nrepositories:\n  - {id: alpha, path: alpha}\n  - {id: bravo, path: bravo}\n"
    )
    scan = ScanEngine().scan_workspace(manifest)
    assert scan.status == ScanStatus.COMPLETED
    assert {(f.provenance.repository_id, f.provenance.module_path) for f in scan.findings} == {
        ("alpha", "wrangler.toml"),
        ("bravo", "wrangler.toml"),
    }
    assert len({f.provenance.evidence_id for f in scan.findings}) == 2
    (a / "link").symlink_to(b, target_is_directory=True)
    (a / "wrangler.json").symlink_to(b / "wrangler.toml")
    files = DiffResolver(a).get_changed_files(
        explicit_files=[
            "wrangler.toml",
            "../bravo/wrangler.toml",
            "link/wrangler.toml",
            str(b / "wrangler.toml"),
            "wrangler.json",
        ]
    )
    assert files == [a / "wrangler.toml"]


@pytest.mark.parametrize(
    ("collection", "primary", "preview", "target", "other"),
    [
        ("kv_namespaces", "id", "preview_id", "1" * 32, "2" * 32),
        (
            "d1_databases",
            "database_id",
            "preview_database_id",
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        ),
        (
            "r2_buckets",
            "bucket_name",
            "preview_bucket_name",
            "one-owned-bucket",
            "two-owned-bucket",
        ),
    ],
)
def test_remote_storage_compares_wrangle_dev_selector_to_deployment(
    tmp_path: Path,
    collection: str,
    primary: str,
    preview: str,
    target: str,
    other: str,
) -> None:
    path = tmp_path / "wrangler.jsonc"
    account, binding = "a" * 32, "OWNED_BINDING"
    local = {"binding": binding, primary: other, preview: target, "remote": True}
    peer = {"binding": "SECOND_BINDING", primary: target, preview: other}
    root = {"account_id": account, collection: [peer], "env": {"receipts": {collection: [local]}}}
    engine = ScanEngine(capture_ai_source=True)

    def scan():
        path.write_text("// Owned configuration fixture\n" + json.dumps(root, indent=2))
        return engine.scan(path)

    result = scan()
    (finding,) = result.findings
    assert finding.rule_id == "AEG-CF-003" and not finding.blocks_ci
    lines = path.read_text().splitlines()
    remote_line = next(i for i, line in enumerate(lines, 1) if '"remote"' in line)
    selector_line = next(i for i, line in enumerate(lines, 1) if f'"{preview}": "{target}"' in line)
    peer_line = next(i for i, line in enumerate(lines, 1) if f'"{primary}": "{target}"' in line)
    assert finding.line_start == remote_line
    assert finding.code_snippet == (
        f"env.receipts.{collection}[0].remote = true (line {remote_line}), "
        f"{preview} (line {selector_line}) matches default.{collection}[0].{primary} "
        f"(line {peer_line})"
    )
    for output in [
        result.model_dump_json(),
        json.dumps(SARIFReporter().generate(result)),
        json.dumps(engine.storage.load_index(str(path))),
    ]:
        for withheld in (target, other, account, binding):
            assert withheld not in output
    assert engine.source_catalog and not engine.source_catalog.files
    assert scan().findings[0].code_snippet == finding.code_snippet
    local[primary], local[preview] = target, other
    assert not scan().findings  # Matching primary, separate preview.
    del local[preview]
    assert scan().findings[0].rule_id == "AEG-CF-003"
    local["remote"] = False
    assert not scan().findings
    del local["remote"]
    assert not scan().findings


def test_storage_locations_follow_toml_array_elements_and_inline_comments(tmp_path: Path) -> None:
    path = tmp_path / "wrangler.toml"
    path.write_text(
        '[[env.books.r2_buckets]]\nbinding = "FIRST"\nbucket_name = "unrelated-bucket"\n'
        '[[env.books.r2_buckets]]\nbinding = "SECOND"\nbucket_name = "shared-bucket"\n'
        '[env."test zone"]\nr2_buckets = [\n  # an array does not index comments\n'
        '  { binding = "SKIP", bucket_name = "unique-bucket" },\n'
        '  { binding = "LOCAL", bucket_name = "local-bucket", '
        'preview_bucket_name = "shared-bucket", remote = true },\n]\n'
    )
    (finding,) = ScanEngine().scan(path).findings
    assert finding.line_start == 11
    assert finding.code_snippet == (
        "environment at line 7.r2_buckets[1].remote = true (line 11), "
        "preview_bucket_name (line 11) matches env.books.r2_buckets[1].bucket_name (line 6)"
    )


@pytest.mark.parametrize(
    "control",
    [
        "same_scope",
        "cross_file",
        "other_account",
        "other_jurisdiction",
        "peer_preview_only",
        "auto_id",
        "placeholder",
        "pages",
        "other_kind",
    ],
)
def test_isolation_exclusions(tmp_path: Path, control: str) -> None:
    local = {"binding": "LOCAL", "bucket_name": "shared-bucket", "remote": True}
    peer = {"binding": "DEPLOY", "bucket_name": "shared-bucket"}
    root, env = {"r2_buckets": [local]}, {"r2_buckets": [peer]}
    doc = {**root, "env": {"archive": env}}
    if control == "same_scope":
        doc = {"r2_buckets": [local, peer]}
    elif control == "cross_file":
        doc = root
        other = tmp_path / "child"
        other.mkdir()
        (other / "wrangler.json").write_text(json.dumps(env))
    elif control == "other_account":
        doc["account_id"] = "a" * 32
        env["account_id"] = "b" * 32
    elif control == "other_jurisdiction":
        peer["jurisdiction"] = "eu"
    elif control == "peer_preview_only":
        peer.update(bucket_name="unique-bucket", preview_bucket_name="shared-bucket")
    elif control == "auto_id":
        del local["bucket_name"], peer["bucket_name"]
    elif control == "placeholder":
        peer["bucket_name"] = local["bucket_name"] = "${BUCKET}"
    elif control == "pages":
        doc["pages_build_output_dir"] = "dist"
    elif control == "other_kind":
        local["bucket_name"] = "a" * 32
        doc["env"] = {"archive": {"kv_namespaces": [{"binding": "DEPLOY", "id": "a" * 32}]}}
    (tmp_path / "wrangler.json").write_text(json.dumps(doc))
    scan = ScanEngine().scan(tmp_path)
    assert scan.status == ScanStatus.COMPLETED and not scan.findings


@pytest.mark.parametrize("bad", [{"remote": "true"}, {"preview_id": None}, "wrong item", None])
def test_invalid_storage_does_not_retain_other_manifest_observations(
    tmp_path: Path, bad: object
) -> None:
    path = tmp_path / "wrangler.json"
    path.write_text(json.dumps({"vars": {"API_TOKEN": CANARY}, "kv_namespaces": [bad]}))
    scan = ScanEngine().scan(path)
    assert scan.status == ScanStatus.PARTIAL and not scan.findings
    assert CANARY not in scan.model_dump_json()


@pytest.mark.parametrize(
    "declaration",
    [
        '[[env."named in TOML".r2_buckets]]\nbinding = "STUDIO"\n'
        'bucket_name = "shared-bucket"\nremote = true',
        'env."named in TOML".r2_buckets = [{ binding = "STUDIO", '
        'bucket_name = "shared-bucket", remote = true }]',
    ],
)
def test_implicit_toml_environment_has_its_own_source_line(
    tmp_path: Path, declaration: str
) -> None:
    path = tmp_path / "wrangler.toml"
    path.write_text(
        "# synthetic worktree\n"
        'r2_buckets = [{ binding = "ARCHIVE", bucket_name = "shared-bucket" }]\n\n'
        + declaration
        + "\n"
    )
    (finding,) = ScanEngine().scan(path).findings
    assert finding.code_snippet.startswith("environment at line 4.r2_buckets[0].remote")
