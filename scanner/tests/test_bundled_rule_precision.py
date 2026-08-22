"""Positive and negative regression fixtures for high-impact bundled rules."""

from pathlib import Path

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
        "def search(request, text):\n"
        "    pattern = request.args.get('pattern')\n"
        "    return re.search(pattern, text)\n",
        "unsafe_redos.py",
    )
    internal_ids = _scan_blocking_rule(
        tmp_path,
        rule_file,
        "def parse(text):\n"
        "    compiled = re.compile(r'(?P<params>[^)]*)')\n"
        "    return compiled.search(text)\n",
        "internal_regex_helper.py",
    )

    assert "AEG-A03-011" in unsafe_ids
    assert "AEG-A03-011" not in internal_ids


def test_redos_rule_retains_constant_regex_signal_as_advisory(tmp_path: Path):
    rule_file = RULES_DIR / "a03-injection" / "injection.yml"
    findings = _scan_findings(
        tmp_path,
        rule_file,
        "def parse(text):\n"
        "    compiled = re.compile(r'(?P<params>[^)]*)')\n"
        "    return compiled.search(text)\n",
        "advisory_internal_regex.py",
    )

    assert "AEG-A03-011" in _advisory_ids(findings)


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
