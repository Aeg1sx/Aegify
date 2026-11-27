"""Positive and negative regression fixtures for high-impact bundled rules."""

import time
from pathlib import Path

import pytest

from aegify.config import AegifyConfig
from aegify.models import EvidenceState, Finding, FindingDisposition
from aegify.scanner.engine import ScanEngine

RULES_DIR = Path(__file__).parent.parent.parent / "rules"


def _scan_findings(tmp_path: Path, rule_file: Path, source: str, name: str) -> list[Finding]:
    target = tmp_path / name
    target.write_text(source)
    config = AegifyConfig()
    config.llm.enabled = False
    config.rules.severity_threshold = "low"
    config.rules.custom_rules = str(rule_file)
    result = ScanEngine(config=config).scan(target)
    return result.findings


def _scan_rule(tmp_path: Path, rule_file: Path, source: str, name: str) -> set[str]:
    return {finding.rule_id for finding in _scan_findings(tmp_path, rule_file, source, name)}


def _scan_blocking_rule(tmp_path: Path, rule_file: Path, source: str, name: str) -> set[str]:
    return {
        finding.rule_id
        for finding in _scan_findings(tmp_path, rule_file, source, name)
        if finding.disposition == FindingDisposition.BLOCKING
    }


def _advisory_ids(findings: list[Finding]) -> set[str]:
    return {
        finding.rule_id
        for finding in findings
        if finding.disposition == FindingDisposition.ADVISORY
    }


def test_ssrf_private_range_rule_requires_url_fetch_evidence(tmp_path: Path):
    rule_file = RULES_DIR / "a10-ssrf" / "ssrf_advanced.yml"

    unsafe_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def proxy(request):\n"
        "    target = request.args.get('url')\n"
        "    return requests.get(target)\n",
        "unsafe_ssrf.py",
    )
    non_network_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def load_config(path):\n"
        "    with open(path) as handle:\n"
        "        return yaml.safe_load(handle)\n",
        "non_network_loader.py",
    )

    assert "AEG-SSRF-ADV-004" in unsafe_ids
    assert "AEG-SSRF-ADV-004" not in non_network_ids


def test_ssrf_private_range_rule_recognizes_private_ip_validation(tmp_path: Path):
    rule_file = RULES_DIR / "a10-ssrf" / "ssrf_advanced.yml"
    safe_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def proxy(request):\n"
        "    target = request.args.get('url')\n"
        "    if is_private(target):\n"
        "        raise ValueError('private address')\n"
        "    return requests.get(target)\n",
        "safe_ssrf.py",
    )

    assert "AEG-SSRF-ADV-004" not in safe_ids


def test_ssrf_taint_rules_require_control_over_url_authority(tmp_path: Path):
    unsafe_source = (
        "def proxy(request):\n"
        "    target = request.args.get('url')\n"
        "    return requests.get(target)\n"
    )
    fixed_origin_source = (
        "def load_repository(request):\n"
        "    owner = request.args.get('owner')\n"
        "    return requests.get(f'https://api.github.com/repos/{owner}')\n"
    )

    base_unsafe = _scan_blocking_rule(
        tmp_path, RULES_DIR / "ssrf.yml", unsafe_source, "unsafe_base_ssrf.py"
    )
    base_fixed = _scan_blocking_rule(
        tmp_path, RULES_DIR / "ssrf.yml", fixed_origin_source, "fixed_base_ssrf.py"
    )
    extra_unsafe = _scan_blocking_rule(
        tmp_path,
        RULES_DIR / "a10-ssrf" / "ssrf_extra.yml",
        unsafe_source,
        "unsafe_extra_ssrf.py",
    )
    extra_fixed = _scan_blocking_rule(
        tmp_path,
        RULES_DIR / "a10-ssrf" / "ssrf_extra.yml",
        fixed_origin_source,
        "fixed_extra_ssrf.py",
    )

    assert "AEG-SSRF-001" in base_unsafe
    assert "AEG-SSRF-001" not in base_fixed
    assert {"AEG-A10-001", "AEG-A10-004"} <= extra_unsafe
    assert not {"AEG-A10-001", "AEG-A10-004"} & extra_fixed


def test_race_rules_require_database_and_business_state_evidence(tmp_path: Path):
    rule_file = RULES_DIR / "a04-insecure-design" / "race_conditions.yml"
    unsafe_ids = _scan_blocking_rule(
        tmp_path,
        rule_file,
        "def debit(account_id):\n"
        "    balance = account_repo.findById(account_id)\n"
        "    balance -= 1\n"
        "    account_repo.save(balance)\n\n"
        "def approve(order_id):\n"
        "    order = order_repo.findById(order_id)\n"
        "    if order.status == 'pending':\n"
        "        order_repo.save(order)\n",
        "unsafe_races.py",
    )
    non_database_ids = _scan_blocking_rule(
        tmp_path,
        rule_file,
        "def render_report(items):\n"
        "    report = items.get('report')\n"
        "    count += 1\n"
        "    store(report)\n\n"
        "def fetch_template():\n"
        "    template = fetch()\n"
        "    if template:\n"
        "        create_report(template)\n",
        "non_database_helpers.py",
    )

    assert "AEG-RACE-003" in unsafe_ids
    assert "AEG-RACE-004" in unsafe_ids
    assert "AEG-RACE-003" not in non_database_ids
    assert "AEG-RACE-004" not in non_database_ids


def test_race_rules_recognize_transaction_control(tmp_path: Path):
    rule_file = RULES_DIR / "a04-insecure-design" / "race_conditions.yml"
    safe_ids = _scan_blocking_rule(
        tmp_path,
        rule_file,
        "def debit(account_id):\n"
        "    with transaction():\n"
        "        balance = account_repo.findById(account_id)\n"
        "        balance -= 1\n"
        "        account_repo.save(balance)\n\n"
        "def approve(order_id):\n"
        "    with transaction():\n"
        "        order = order_repo.findById(order_id)\n"
        "        if order.status == 'pending':\n"
        "            order_repo.save(order)\n",
        "safe_races.py",
    )

    assert "AEG-RACE-003" not in safe_ids
    assert "AEG-RACE-004" not in safe_ids


def test_code_injection_rule_uses_function_constructor_calls_not_words(tmp_path: Path):
    rule_file = RULES_DIR / "a03-injection" / "injection.yml"
    unsafe_ids = _scan_rule(
        tmp_path,
        rule_file,
        "export function compile(req: any) {\n  return Function(req.body.source);\n}\n",
        "unsafe_function.ts",
    )
    unrelated_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def invoke(function, request):\n    return function(request)\n",
        "function_metadata.py",
    )

    assert "AEG-A03-007" in unsafe_ids
    assert "AEG-A03-007" not in unrelated_ids


def test_workflow_bypass_rule_requires_later_step_endpoint_evidence(tmp_path: Path):
    rule_file = RULES_DIR / "a04-insecure-design" / "business_logic.yml"
    unsafe_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def register_routes(app):\n    app.post('/checkout/step-2', finalize_order)\n",
        "unsafe_workflow.py",
    )
    unrelated_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def render_stage_view(stage, view):\n    handler = view\n    return handler(stage)\n",
        "workflow_ui_helper.py",
    )

    assert "AEG-LOGIC-003" in unsafe_ids
    assert "AEG-LOGIC-003" not in unrelated_ids


def test_workflow_bypass_rule_recognizes_prerequisite_guard(tmp_path: Path):
    rule_file = RULES_DIR / "a04-insecure-design" / "business_logic.yml"
    safe_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def register_routes(app):\n"
        "    validate_prerequisite('checkout')\n"
        "    app.post('/checkout/step-2', finalize_order)\n",
        "safe_workflow.py",
    )

    assert "AEG-LOGIC-003" not in safe_ids


def test_oauth_scope_rule_requires_oauth_flow_evidence(tmp_path: Path):
    rule_file = RULES_DIR / "a07-auth-failures" / "oauth_security.yml"
    unsafe_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def oauth_callback(scope, token):\n    return exchange_code(token)\n",
        "unsafe_oauth_scope.py",
    )
    unrelated_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def summarize_scope(scope, token_count):\n"
        "    return {'scope': scope, 'tokens': token_count}\n",
        "scope_report.py",
    )

    assert "AEG-OAUTH-004" in unsafe_ids
    assert "AEG-OAUTH-004" not in unrelated_ids


def test_oauth_scope_rule_recognizes_scope_validation(tmp_path: Path):
    rule_file = RULES_DIR / "a07-auth-failures" / "oauth_security.yml"
    safe_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def oauth_callback(scope, token):\n"
        "    validate_scope(scope)\n"
        "    return exchange_code(token)\n",
        "safe_oauth_scope.py",
    )

    assert "AEG-OAUTH-004" not in safe_ids


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (
            "oauth_request.py",
            'def begin(oauth):\n    return oauth.authorization_url("/authorize", scope="admin")\n',
        ),
        ("oauth_config.py", 'OAUTH_SCOPE = "full_access"\n'),
        (
            "oauth_provider.ts",
            'function begin() { return GitHub({authorization: {params: {scope: "*"}}}); }\n',
        ),
        (
            "oauth_array.ts",
            'function begin() { return OAuth2Client({scope: ["profile", "admin"]}); }\n',
        ),
        ("oauth_config_array.py", 'OAUTH_SCOPES = ["profile",\n    "admin"]\n'),
    ],
)
def test_oauth_scope_review_preserves_explicit_high_privilege_signals(
    tmp_path: Path, name: str, source: str
):
    findings = _scan_findings(
        tmp_path, RULES_DIR / "a07-auth-failures/oauth_security.yml", source, name
    )
    oauth = [finding for finding in findings if finding.rule_id == "AEG-OAUTH-004"]
    assert oauth
    assert all(finding.disposition == FindingDisposition.ADVISORY for finding in oauth)
    assert all(finding.evidence_state == EvidenceState.CANDIDATE for finding in oauth)


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (
            "metadata.py",
            'def summarize_scope(scope):\n    return {"scope": scope, "role": "admin"}\n',
        ),
        (
            "project.ts",
            "function projectScope(principal) {\n"
            '  return principal.workspaceAdmin ? {} : {scope: "project"};\n}\n',
        ),
        (
            "readonly_oauth.py",
            "def begin(oauth):\n"
            '    return oauth.authorization_url("/authorize", scope="profile", '
            'redirect_uri="/admin")\n',
        ),
        ("readonly_config.py", 'OAUTH_SCOPE = "profile"\nother_role = "admin"\n'),
        ("unrelated_token.py", "def local_cache():\n    return get_token()\n"),
        (
            "named_decoy.py",
            'def callback():\n    return unrelated_authorization_url(scope="admin")\n',
        ),
    ],
)
def test_oauth_scope_review_rejects_non_oauth_and_separate_value_decoys(
    tmp_path: Path, name: str, source: str
):
    ids = _scan_rule(tmp_path, RULES_DIR / "a07-auth-failures/oauth_security.yml", source, name)
    assert "AEG-OAUTH-004" not in ids


def test_oauth_scope_review_stays_bounded_for_repeated_scope_metadata(tmp_path: Path):
    from aegify.rules.yaml_rule import load_yaml_rules
    from aegify.scanner.ast_parser import ASTParser
    from aegify.scanner.call_graph import CallGraphBuilder

    target = tmp_path / "metadata.py"
    target.write_text('scope = "project"\nother_role = "admin"\n' * 1000)
    ast = ASTParser().parse_file(target)
    rule = next(
        rule
        for rule in load_yaml_rules(RULES_DIR / "a07-auth-failures/oauth_security.yml")
        if rule.definition.id == "AEG-OAUTH-004"
    )
    started = time.monotonic()
    assert rule.evaluate([ast], CallGraphBuilder().build([ast]), []) == []
    assert time.monotonic() - started < 2


def test_unsafe_api_consumption_requires_response_to_sensitive_sink_flow(tmp_path: Path):
    rule_file = RULES_DIR / "api-security" / "api_advanced.yml"
    unsafe_ids = _scan_blocking_rule(
        tmp_path,
        rule_file,
        "def execute_remote_job():\n"
        "    response = requests.get('https://jobs.example.test/next')\n"
        "    return os.system(response.text)\n",
        "unsafe_api_response.py",
    )
    read_only_ids = _scan_blocking_rule(
        tmp_path,
        rule_file,
        "def health_check():\n"
        "    response = requests.get('https://status.example.test/health')\n"
        "    return response.status_code\n",
        "read_only_api_response.py",
    )

    assert "AEG-API-010" in unsafe_ids
    assert "AEG-API-010" not in read_only_ids


def test_unsafe_api_consumption_retains_broad_signal_as_advisory(tmp_path: Path):
    rule_file = RULES_DIR / "api-security" / "api_advanced.yml"
    findings = _scan_findings(
        tmp_path,
        rule_file,
        "def health_check():\n"
        "    response = requests.get('https://status.example.test/health')\n"
        "    return response.status_code\n",
        "advisory_api_response.py",
    )

    assert "AEG-API-010" in _advisory_ids(findings)


def test_unsafe_api_consumption_recognizes_response_validation(tmp_path: Path):
    rule_file = RULES_DIR / "api-security" / "api_advanced.yml"
    safe_ids = _scan_blocking_rule(
        tmp_path,
        rule_file,
        "def execute_remote_job():\n"
        "    response = requests.get('https://jobs.example.test/next')\n"
        "    command = validate_command(response.json())\n"
        "    return os.system(command)\n",
        "validated_api_response.py",
    )

    assert "AEG-API-010" not in safe_ids


def test_redos_rule_requires_user_controlled_pattern_evidence(tmp_path: Path):
    rule_file = RULES_DIR / "a03-injection" / "injection.yml"
    unsafe_ids = _scan_blocking_rule(
        tmp_path,
        rule_file,
        "import re\ndef search(request, text):\n"
        "    pattern = request.args.get('pattern')\n"
        "    return re.search(pattern, text)\n",
        "unsafe_redos.py",
    )
    internal_ids = _scan_blocking_rule(
        tmp_path,
        rule_file,
        "import re\ndef parse(text):\n"
        "    compiled = re.compile(r'(?P<params>[^)]*)')\n"
        "    return compiled.search(text)\n",
        "internal_regex_helper.py",
    )

    assert "AEG-A03-011" in unsafe_ids
    assert "AEG-A03-011" not in internal_ids


def test_redos_rule_excludes_fixed_patterns_from_advisories(tmp_path: Path):
    rule_file = RULES_DIR / "a03-injection" / "injection.yml"
    findings = _scan_findings(
        tmp_path,
        rule_file,
        "import re\ndef parse(text):\n"
        "    compiled = re.compile(r'(?P<params>[^)]*)')\n"
        "    return compiled.search(text)\n",
        "advisory_internal_regex.py",
    )

    assert "AEG-A03-011" not in _advisory_ids(findings)


def test_format_string_rule_only_treats_first_argument_as_format(tmp_path: Path):
    rule_file = RULES_DIR / "a03-injection" / "injection.yml"
    unsafe_ids = _scan_blocking_rule(
        tmp_path,
        rule_file,
        "def log(request):\n    logger.info(request.args.get('format'), 'value')\n",
        "unsafe_format.py",
    )
    parameterized_ids = _scan_blocking_rule(
        tmp_path,
        rule_file,
        "def log(request):\n    logger.info('user=%s', request.args.get('user'))\n",
        "parameterized_logging.py",
    )

    assert "AEG-A03-012" in unsafe_ids
    assert "AEG-A03-012" not in parameterized_ids


def test_format_string_rule_emits_receiver_taint_evidence(tmp_path: Path):
    target = tmp_path / "unsafe_template.py"
    target.write_text(
        "def render(request):\n"
        "    template = request.args.get('template')\n"
        "    return template.format('value')\n"
    )
    config = AegifyConfig()
    config.llm.enabled = False
    config.rules.severity_threshold = "low"
    config.rules.custom_rules = str(RULES_DIR / "a03-injection" / "injection.yml")

    findings = [
        finding
        for finding in ScanEngine(config=config).scan(target).findings
        if finding.rule_id == "AEG-A03-012"
    ]

    assert any(
        finding.taint_flow is not None
        and finding.taint_flow.sink.argument_index == -1
        and finding.taint_flow.sink.sink_type == "string_format"
        and finding.evidence_state == EvidenceState.REACHABLE
        and finding.disposition == FindingDisposition.BLOCKING
        for finding in findings
    )


def test_session_timeout_rule_matches_exact_token_calls_only(tmp_path: Path):
    rule_file = RULES_DIR / "asvs-extras" / "asvs.yml"
    unsafe_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def create_token(payload):\n    return sign(payload)\n",
        "unsafe_token.py",
    )
    unrelated_ids = _scan_rule(
        tmp_path,
        rule_file,
        "def compare(value):\n    return _is_assignable(value)\n",
        "type_helper.py",
    )

    assert "AEG-ASVS-001" in unsafe_ids
    assert "AEG-ASVS-001" not in unrelated_ids


@pytest.mark.parametrize(
    ("rule_file", "rule_id"),
    [
        ("a03-injection/injection.yml", "AEG-A03-007"),
        ("a06-vulnerable-components/dependency_patterns.yml", "AEG-DEP-005"),
        ("rce/javascript_rce.yml", "AEG-RCE-JS-003"),
    ],
)
def test_javascript_dollar_names_and_real_eval(tmp_path, rule_file, rule_id):
    pack = RULES_DIR / rule_file
    page = (
        'function names(panel) { return panel.$$eval("li", rows => '
        'rows.map(row => row.querySelector("span").textContent)); }\n'
        'function field(p, input) { return p.$eval("div", n => n.textContent, input); }'
    )
    assert rule_id not in _scan_rule(tmp_path, pack, page, "browser.mjs")
    assert rule_id in _scan_rule(
        tmp_path, pack, "function render(req) { return eval(req.body.input); }", "handler.mjs"
    )


def test_function_constructor_still_reviews_request_argument(tmp_path):
    pack = RULES_DIR / "a06-vulnerable-components/dependency_patterns.yml"
    source = "function render(req) { return new Function(req.body.input); }"
    assert "AEG-DEP-005" in _scan_rule(tmp_path, pack, source, "constructor.mjs")


def test_race_advisories_require_store_operations(tmp_path):
    pack = RULES_DIR / "a04-insecure-design/race_conditions.yml"
    local = (
        "function view(review, index) {\n"
        "  const selected = review.files[index];\n"
        "  const next = index + 1;\n"
        "  return restoreSelection(selected, next);\n}"
    )
    assert "AEG-RACE-003" not in _scan_rule(tmp_path, pack, local, "view.tsx")
    writes = (
        "def update(repo, key):\n    item = repo.get(key)\n"
        "    item.total = 3\n    repo.save(item)\n"
    )
    assert "AEG-RACE-003" in _scan_rule(tmp_path, pack, writes, "ledger.py")
    io = (
        "def copy(source, target):\n    buf = source.read()\n"
        "    buf[0] = 0\n    target.write(buf)\n"
    )
    assert "AEG-RACE-003" not in _scan_rule(tmp_path, pack, io, "copy.py")
    store = (
        "def edit(order_store, key):\n    record = order_store.read(key)\n"
        "    record.count += 1\n    order_store.write(record)\n"
    )
    assert "AEG-RACE-003" in _scan_rule(tmp_path, pack, store, "store.py")


def test_quantity_review_requires_a_submitted_quantity(tmp_path):
    pack = RULES_DIR / "a04-insecure-design/business_logic.yml"
    local = (
        "def analyze(params):\n    visits = Counter()\n    return params.get('language'), visits\n"
    )
    assert "AEG-LOGIC-002" not in _scan_rule(tmp_path, pack, local, "analyzer.py")
    body = "def checkout(request):\n    return request.data['quantity']\n"
    assert "AEG-LOGIC-002" in _scan_rule(tmp_path, pack, body, "checkout.py")


def test_reset_credential_assignment_and_constant_vocabulary(tmp_path):
    pack = RULES_DIR / "a07-auth-failures/password_security.yml"
    words = (
        'def metadata(user_id):\n    keys = {"reset_token", "email"}\n    return keys, user_id\n'
    )
    assert "AEG-PASS-005" not in _scan_rule(tmp_path, pack, words, "metadata.py")
    for i, expr in enumerate(("time.time()", "str(user.email)")):
        body = f'def issue(session, user):\n    session["reset_token"] = {expr}\n'
        assert "AEG-PASS-005" in _scan_rule(tmp_path, pack, body, f"reset{i}.py")


def test_upload_rule_distinguishes_request_files_from_browser_file_selection(tmp_path: Path):
    findings = _scan_findings(
        tmp_path,
        RULES_DIR / "a01-broken-access-control" / "access_control.yml",
        "async function selectFile(page, path) {\n"
        "  const ready = waitForUpload();\n"
        "  await page.uploadFile(path);\n"
        "  await ready;\n"
        "}\n"
        "function storeRequest(req) {\n"
        "  return storage.uploadFile(req.file);\n"
        "}\n"
        "function configure() { return multer({}); }\n",
        "upload.js",
    )
    assert {finding.line_start for finding in findings if finding.rule_id == "AEG-A01-007"} == {
        7,
        9,
    }


@pytest.mark.parametrize("owner", ["stored", "allocation"])
def test_timing_rule_distinguishes_navigation_hash_from_credential_comparisons(
    tmp_path: Path, owner: str
):
    findings = _scan_findings(
        tmp_path,
        RULES_DIR / "a02-cryptographic-failures" / "javascript_crypto.yml",
        "function navigate() { return window.location.hash === '#reports'; }\n"
        "function link() { return globalThis.location?.hash !== '#details'; }\n"
        f"function verify({owner}, candidate) {{ return {owner}.hash === candidate; }}\n"
        "function authorize(value, token) { return value !== token; }\n",
        "compare.js",
    )
    assert {
        finding.line_start for finding in findings if finding.rule_id == "AEG-CRYPTO-JS-005"
    } == {3, 4}


@pytest.mark.parametrize(
    ("name", "source", "expected"),
    [
        (
            "page.tsx",
            'const hasRouteCounts = receipt.status === "completed";\n'
            'setResult({ state: "saved", count: hasRouteCounts });\n',
            False,
        ),
        (
            "ui.js",
            "router.get('/status', showCompleted);\nconst text = '/checkout/confirm';\n",
            False,
        ),
        (
            "workflow.py",
            "@checkout.post('/orders/confirm')\ndef submit(): return publish()\n",
            True,
        ),
        (
            "Order.java",
            'class Order {\n@PostMapping(path = "/checkout/stage-10")\n'
            "public void submit() {}\n}\n",
            True,
        ),
        (
            "router.go",
            'package shop\nfunc routes(){ http.HandleFunc("/order/complete", finish) }\n',
            True,
        ),
    ],
)
def test_workflow_rule_matches_the_registered_route_path(tmp_path: Path, name, source, expected):
    found = _scan_rule(
        tmp_path, RULES_DIR / "a04-insecure-design" / "business_logic.yml", source, name
    )
    assert ("AEG-LOGIC-003" in found) is expected


@pytest.mark.parametrize(
    ("name", "source", "expected"),
    [
        (
            "lookup.py",
            "def resolve_account(root, info, id):\n"
            "    key = str(id)\n"
            "    return Account.objects.get(pk=key)\n",
            True,
        ),
        (
            "resolver.js",
            "const field = { resolve(parent, args) { return store.findById(args.id); } };",
            True,
        ),
        (
            "map.js",
            "const resolvers = { Query: { node: (_, { id }) => database.findById(id) } };",
            True,
        ),
        (
            "resolver.ts",
            "const query = { resolve(parent: Source, args: Args) { "
            "return store.findById(args.id); } };",
            True,
        ),
        (
            "Account.java",
            "class AccountQuery { @QueryMapping Account account(String id) { "
            "return repository.findById(id); } }",
            True,
        ),
        (
            "authorized.py",
            "def resolve_account(root, info, id):\n"
            "    if not has_permission(info.context.user, id):\n"
            "        raise PermissionError()\n"
            "    return Account.objects.get(pk=id)\n",
            False,
        ),
        (
            "viewer.py",
            "def resolve_account(root, info, id):\n"
            "    return Account.objects.get(pk=id, owner=info.context.user)\n",
            False,
        ),
        (
            "unrelated.js",
            "const f = { resolve(parent, args) { const id = args.id; "
            "return store.findOne({active: true}); } };",
            False,
        ),
        (
            "parser.py",
            "def query(self, call: Node) -> QueryExpression:\n"
            "    node = call.child_by_field_name('object')\n"
            "    return self.lookup(node)\n",
            False,
        ),
        (
            "store.py",
            "def query(self, id):\n    node = Account.objects.get(pk=id)\n    return node\n",
            False,
        ),
        (
            "schema.py",
            "def resolve_label(root, info, id):\n    return str(id)\n",
            False,
        ),
    ],
)
def test_graphql_object_lookup_requires_resolver_and_storage(tmp_path, name, source, expected):
    ids = _scan_rule(tmp_path, RULES_DIR / "api-security" / "bola.yml", source, name)
    assert ("AEG-BOLA-004" in ids) is expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "def advance(cache, key):\n    item = cache.get(key)\n"
            "    item['total'] += 1\n    cache.put(key, item)\n",
            True,
        ),
        (
            "def advance(key):\n    item = Account.objects.get(pk=key)\n"
            "    item.value += 1\n    item.save()\n",
            True,
        ),
        (
            "def advance(cursor, key):\n    cursor.execute('SELECT total FROM counts')\n"
            "    total = cursor.fetchone()[0]\n    total += 1\n"
            "    cursor.execute('UPDATE counts SET total=?', (total,))\n",
            True,
        ),
        (
            "def transport(env):\n    value = os.environ.get('CA_FILE')\n"
            "    env['certificate'] = value\n    env.update(mode='tls')\n",
            False,
        ),
        (
            "def render(settings, props):\n    item = settings.get('size')\n"
            "    props['size'] = item\n    props.update(done=True)\n",
            False,
        ),
        (
            "def read(cache, key):\n    return cache.get(key)\n"
            "def write(cache, key, item):\n    item.count += 1\n    cache.put(key, item)\n",
            False,
        ),
    ],
)
def test_race_advisory_uses_storage_operations_in_one_function(tmp_path, source, expected):
    rule_file = RULES_DIR / "a04-insecure-design" / "race_conditions.yml"
    findings = _scan_findings(tmp_path, rule_file, source, "storage.py")
    assert ("AEG-RACE-003" in _advisory_ids(findings)) is expected


@pytest.mark.parametrize(
    ("pack", "rule", "code", "expected"),
    [
        (
            "a04-insecure-design/business_logic.yml",
            "AEG-LOGIC-001",
            "function checkout(req) { return charge(req.body.price); }",
            True,
        ),
        (
            "a04-insecure-design/business_logic.yml",
            "AEG-LOGIC-001",
            "function checkout(request) { return request.getParameter('discount'); }",
            True,
        ),
        (
            "a04-insecure-design/business_logic.yml",
            "AEG-LOGIC-001",
            "function orders(params) { const total = rows.length; return params.get('scanId'); }",
            False,
        ),
        (
            "a04-insecure-design/business_logic.yml",
            "AEG-LOGIC-004",
            "function edit(req, account) { account.role = req.body.role; return account.save(); }",
            True,
        ),
        (
            "a04-insecure-design/business_logic.yml",
            "AEG-LOGIC-004",
            "function edit(params, user) { const role = params['role']; user.update({role}); }",
            True,
        ),
        (
            "a04-insecure-design/business_logic.yml",
            "AEG-LOGIC-004",
            'function render(params) { setFilters(params); return <p role="alert">Review</p>; }',
            False,
        ),
        (
            "a06-vulnerable-components/dependency_patterns.yml",
            "AEG-DEP-002",
            "function render() { return $(location.hash); }",
            True,
        ),
        (
            "a06-vulnerable-components/dependency_patterns.yml",
            "AEG-DEP-002",
            "function render(userInput) { return $(userInput); }",
            True,
        ),
        (
            "a06-vulnerable-components/dependency_patterns.yml",
            "AEG-DEP-002",
            "function render() { return window.jQuery(location.search); }",
            True,
        ),
        (
            "a06-vulnerable-components/dependency_patterns.yml",
            "AEG-DEP-002",
            """function row(panel) { return panel.$('li a[href^="/findings?"]'); }""",
            False,
        ),
        (
            "a06-vulnerable-components/dependency_patterns.yml",
            "AEG-DEP-002",
            "function row() { return $('#search-input'); }",
            False,
        ),
        (
            "a06-vulnerable-components/dependency_patterns.yml",
            "AEG-DEP-002",
            "function render() { const v = window.name; $('#result').html(v); }",
            True,
        ),
        (
            "a06-vulnerable-components/dependency_patterns.yml",
            "AEG-DEP-002",
            "function render() { $('#result').append(location.hash); }",
            True,
        ),
        (
            "a06-vulnerable-components/dependency_patterns.yml",
            "AEG-DEP-002",
            """function doc() { return ["args.append('input')", "$(x)", "location.hash"]; }""",
            False,
        ),
        (
            "a06-vulnerable-components/dependency_patterns.yml",
            "AEG-DEP-002",
            "function read(user) { return $('#result').html(); }",
            False,
        ),
        (
            "api-security/api_advanced.yml",
            "AEG-API-014",
            "function records(store) { return store.getAll(); }",
            True,
        ),
        (
            "api-security/api_advanced.yml",
            "AEG-API-014",
            "function records(store, tenant) { return store.getAll(tenant); }",
            True,
        ),
        (
            "api-security/api_advanced.yml",
            "AEG-API-014",
            "function filters(params, key) { return params.getAll(key); }",
            False,
        ),
        (
            "a07-auth-failures/session_management.yml",
            "AEG-SESS-003",
            """function linkFor(session) { const url = "/view?sid=" + session.id; return url; }""",
            True,
        ),
        (
            "a07-auth-failures/session_management.yml",
            "AEG-SESS-003",
            """function next(session_id) { return redirect("/done?sid=" + session_id); }""",
            True,
        ),
        (
            "a07-auth-failures/session_management.yml",
            "AEG-SESS-003",
            """import { scanFindingsHref } from "./views";
function openView(scope) { return new URL(scanFindingsHref("scan-A", scope)).searchParams; }
function label() { return "How is the session?"; }""",
            False,
        ),
    ],
)
def test_review_rules_bind_the_reported_operation(tmp_path, pack, rule, code, expected):
    findings = _scan_rule(tmp_path, RULES_DIR / pack, code, "review.tsx")
    assert (rule in findings) is expected
