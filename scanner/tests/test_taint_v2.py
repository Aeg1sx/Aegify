"""Regression tests for global flow/field/object-sensitive taint analysis."""

import json
from pathlib import Path

from aegify.config import AegifyConfig
from aegify.ir import ProgramGraphBuilder
from aegify.models import Language
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.call_graph import CallGraphBuilder
from aegify.scanner.dataflow import DataflowAnalyzer, SinkPattern, TaintConfig
from aegify.scanner.engine import ScanEngine


def _analyze(directory: Path, config: TaintConfig | None = None):
    asts = ASTParser().parse_directory(directory)
    call_graph = CallGraphBuilder().build(asts)
    program_graph = ProgramGraphBuilder().build(asts).graph
    analyzer = DataflowAnalyzer(config=config)
    flows = analyzer.analyze(asts, call_graph, program_graph)
    return flows, analyzer.summary


def test_unrelated_source_and_sink_in_same_function_do_not_form_a_flow(
    tmp_path: Path,
):
    (tmp_path / "app.py").write_text(
        "import os\n"
        "from flask import request\n"
        "def handler():\n"
        "    user_value = request.args.get('command')\n"
        "    safe_value = 'uptime'\n"
        "    os.system(safe_value)\n"
    )

    flows, summary = _analyze(tmp_path)

    assert summary.sources == 1
    assert summary.sinks == 1
    assert flows == []


def test_java_taint_crosses_argument_and_allocation_site_field(tmp_path: Path):
    (tmp_path / "CommandController.java").write_text(
        "class Payload { String value; }\n"
        "class CommandController {\n"
        "  private final CommandService service = new CommandService();\n"
        '  @PostMapping("/run")\n'
        "  void run(String input) {\n"
        "    Payload tainted = new Payload();\n"
        "    Payload safe = new Payload();\n"
        "    tainted.value = input;\n"
        '    safe.value = "uptime";\n'
        "    service.execute(tainted);\n"
        "  }\n"
        "}\n"
    )
    (tmp_path / "CommandService.java").write_text(
        "class CommandService {\n"
        "  void execute(Payload payload) {\n"
        "    String command = payload.value;\n"
        "    Runtime.getRuntime().exec(command);\n"
        "  }\n"
        "}\n"
    )

    flows, summary = _analyze(tmp_path)

    command_flows = [flow for flow in flows if flow.sink.sink_type == "os_command"]
    assert len(command_flows) == 1
    propagation = [step.propagation_type for step in command_flows[0].path]
    assert "field-store" in propagation
    assert "argument" in propagation
    assert "field-load" in propagation
    assert propagation[-1] == "sink"
    assert summary.argument_propagations >= 1
    assert summary.field_reads >= 1
    assert summary.field_writes >= 1
    assert summary.heap_objects >= 2


def test_allocation_sites_keep_safe_and_tainted_objects_separate(tmp_path: Path):
    (tmp_path / "Objects.java").write_text(
        "class Box { String value; }\n"
        "class Objects {\n"
        '  @PostMapping("/run")\n'
        "  void run(String input) {\n"
        "    Box tainted = new Box();\n"
        "    Box safe = new Box();\n"
        "    tainted.value = input;\n"
        '    safe.value = "uptime";\n'
        "    Runtime.getRuntime().exec(safe.value);\n"
        "  }\n"
        "}\n"
    )

    flows, summary = _analyze(tmp_path)

    assert summary.heap_objects >= 2
    assert flows == []


def test_taint_summary_propagates_return_values(tmp_path: Path):
    (tmp_path / "Returns.java").write_text(
        "class Returns {\n"
        "  String echo(String value) { return value; }\n"
        '  @PostMapping("/run")\n'
        "  void run(String input) {\n"
        "    String command = echo(input);\n"
        "    Runtime.getRuntime().exec(command);\n"
        "  }\n"
        "}\n"
    )

    flows, summary = _analyze(tmp_path)

    assert len(flows) == 1
    assert "return" in [step.propagation_type for step in flows[0].path]
    assert any(step.call_context for step in flows[0].path)
    assert summary.return_propagations >= 1
    assert summary.context_depth == 2
    assert summary.contexts_analyzed >= 2


def test_object_return_summary_preserves_allocation_field_identity(tmp_path: Path):
    (tmp_path / "ObjectReturns.java").write_text(
        "class Box { String value; }\n"
        "class ObjectReturns {\n"
        "  Box build(String input) {\n"
        "    Box result = new Box();\n"
        "    result.value = input;\n"
        "    return result;\n"
        "  }\n"
        '  @PostMapping("/run")\n'
        "  void run(String input) {\n"
        "    Box returned = build(input);\n"
        "    Runtime.getRuntime().exec(returned.value);\n"
        "  }\n"
        "}\n"
    )

    flows, summary = _analyze(tmp_path)

    assert len(flows) == 1
    propagation = [step.propagation_type for step in flows[0].path]
    assert "field-store" in propagation
    assert "return" in propagation
    assert "field-load" in propagation
    assert summary.object_return_propagations >= 1
    assert summary.heap_strong_updates >= 1


def test_object_return_context_does_not_leak_tainted_heap_to_safe_caller(
    tmp_path: Path,
):
    (tmp_path / "ObjectReturnContexts.java").write_text(
        "class Box { String value; }\n"
        "class ObjectReturnContexts {\n"
        "  Box build(String value) {\n"
        "    Box result = new Box();\n"
        "    result.value = value;\n"
        "    return result;\n"
        "  }\n"
        '  @PostMapping("/tainted")\n'
        "  void tainted(String input) { build(input); }\n"
        "  void safe() {\n"
        '    Box result = build("uptime");\n'
        "    Runtime.getRuntime().exec(result.value);\n"
        "  }\n"
        "}\n"
    )

    flows, summary = _analyze(tmp_path)

    assert flows == []
    assert summary.object_return_propagations >= 2


def test_singleton_heap_field_safe_overwrite_is_a_strong_update(tmp_path: Path):
    (tmp_path / "StrongUpdate.java").write_text(
        "class Box { String value; }\n"
        "class StrongUpdate {\n"
        '  @PostMapping("/run")\n'
        "  void run(String input) {\n"
        "    Box box = new Box();\n"
        "    box.value = input;\n"
        '    box.value = "uptime";\n'
        "    Runtime.getRuntime().exec(box.value);\n"
        "  }\n"
        "}\n"
    )

    flows, summary = _analyze(tmp_path)

    assert flows == []
    assert summary.field_writes >= 2
    assert summary.heap_strong_updates >= 2


def test_sanitizer_state_survives_assignment_to_sink(tmp_path: Path):
    (tmp_path / "safe.py").write_text(
        "import os\n"
        "import shlex\n"
        "from flask import request\n"
        "def handler():\n"
        "    user_value = request.args.get('command')\n"
        "    safe_value = shlex.quote(user_value)\n"
        "    os.system(safe_value)\n"
    )

    flows, _ = _analyze(tmp_path)

    assert len(flows) == 1
    assert flows[0].sanitized is True
    assert flows[0].sanitizer == "shlex.quote"


def test_taint_propagates_through_interpolated_strings(tmp_path: Path):
    (tmp_path / "query.py").write_text(
        "from flask import request\n"
        "def handler(cursor):\n"
        "    user_value = request.args.get('name')\n"
        "    query = f\"SELECT * FROM users WHERE name = '{user_value}'\"\n"
        "    cursor.execute(query)\n"
    )

    flows, _ = _analyze(tmp_path)

    assert len(flows) == 1
    assert flows[0].sink.sink_type == "sql_query"
    assert any(step.variable == "query" for step in flows[0].path)


def test_typescript_property_source_uses_javascript_model(tmp_path: Path):
    (tmp_path / "handler.ts").write_text(
        "function handler(req) {\n  const command = req.query.command;\n  exec(command);\n}\n"
    )

    flows, summary = _analyze(tmp_path)

    assert summary.sources == 1
    assert len(flows) == 1
    assert flows[0].source.source_type == "http_param"
    assert flows[0].sink.sink_type == "os_command"


def test_taint_inside_try_block_is_not_hidden_by_control_node(tmp_path: Path):
    (tmp_path / "TryFlow.java").write_text(
        "class TryFlow {\n"
        '  @PostMapping("/run")\n'
        "  void run(String input) {\n"
        "    try { Runtime.getRuntime().exec(input); }\n"
        "    catch (Exception error) { System.out.println(error); }\n"
        "  }\n"
        "}\n"
    )

    flows, summary = _analyze(tmp_path)

    assert len(flows) == 1
    assert flows[0].sink.sink_type == "os_command"
    assert summary.flows == 1


def test_shared_identity_summary_does_not_mix_safe_and_tainted_callers(
    tmp_path: Path,
):
    (tmp_path / "Contexts.java").write_text(
        "class Contexts {\n"
        "  String identity(String value) { return value; }\n"
        '  @PostMapping("/tainted")\n'
        "  void tainted(String input) { identity(input); }\n"
        "  void safe() {\n"
        '    String command = identity("uptime");\n'
        "    Runtime.getRuntime().exec(command);\n"
        "  }\n"
        "}\n"
    )

    flows, _ = _analyze(tmp_path)

    assert flows == []


def test_jvm_library_summary_tracks_string_builder_receiver_state(tmp_path: Path):
    (tmp_path / "BuilderFlow.java").write_text(
        "class BuilderFlow {\n"
        '  @PostMapping("/run")\n'
        "  void run(String input) {\n"
        "    StringBuilder builder = new StringBuilder();\n"
        "    builder.append(input);\n"
        "    String command = builder.toString();\n"
        "    Runtime.getRuntime().exec(command);\n"
        "  }\n"
        "}\n"
    )

    flows, summary = _analyze(tmp_path)

    assert len(flows) == 1
    assert any(step.propagation_type == "library-summary" for step in flows[0].path)
    assert summary.library_model_pack == "2026.08.1"
    assert summary.library_models_loaded >= 9
    assert summary.library_summary_applications >= 2


def test_jvm_library_source_and_process_builder_sink_are_modeled(tmp_path: Path):
    (tmp_path / "LibraryBoundaries.java").write_text(
        "class LibraryBoundaries {\n"
        "  void fromEnvironment() {\n"
        '    String command = System.getenv("COMMAND");\n'
        "    Runtime.getRuntime().exec(command);\n"
        "  }\n"
        '  @PostMapping("/run")\n'
        "  void fromHttp(String input) {\n"
        "    ProcessBuilder builder = new ProcessBuilder();\n"
        "    builder.command(input);\n"
        "  }\n"
        "}\n"
    )

    flows, summary = _analyze(tmp_path)

    assert {flow.source.source_type for flow in flows} >= {
        "environment_variable",
        "http_param",
    }
    assert any(flow.sink.function == "builder.command" for flow in flows)
    assert summary.library_summary_applications >= 2


def test_jvm_sanitizer_summary_is_scoped_to_sink_category(tmp_path: Path):
    (tmp_path / "ContextualSanitizer.java").write_text(
        "class ContextualSanitizer {\n"
        '  @PostMapping("/run")\n'
        "  void run(String input) {\n"
        "    String safe = encoder.encodeForHTML(input);\n"
        "    response.write(safe);\n"
        "    Runtime.getRuntime().exec(safe);\n"
        "  }\n"
        "}\n"
    )
    config = TaintConfig.default()
    config.sinks[Language.JAVA] = [
        SinkPattern("response.write", "xss", 0),
        SinkPattern("Runtime.exec", "os_command", 0),
    ]

    flows, _ = _analyze(tmp_path, config)

    by_sink = {flow.sink.sink_type: flow for flow in flows}
    assert by_sink["xss"].sanitized is True
    assert by_sink["xss"].sanitizer == "org.owasp.esapi.encoder.encodeforhtml"
    assert by_sink["os_command"].sanitized is False
    assert by_sink["os_command"].sanitizer is None


def test_workspace_taint_crosses_repository_boundary(tmp_path: Path):
    consumer = tmp_path / "consumer"
    provider = tmp_path / "provider"
    consumer.mkdir()
    provider.mkdir()
    (consumer / "Entry.java").write_text(
        "class Entry {\n"
        '  @PostMapping("/run")\n'
        "  void run(String input) {\n"
        "    Remote remote = new Remote();\n"
        "    remote.executeRemote(input);\n"
        "  }\n"
        "}\n"
    )
    (provider / "Remote.java").write_text(
        "class Remote {\n"
        "  void executeRemote(String command) {\n"
        "    Runtime.getRuntime().exec(command);\n"
        "  }\n"
        "}\n"
    )
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\n"
        "repositories:\n"
        "  - id: consumer\n"
        "    path: ./consumer\n"
        "    depends_on: [provider]\n"
        "  - id: provider\n"
        "    path: ./provider\n"
    )
    config = AegifyConfig()
    config.llm.enabled = False
    config.rules.severity_threshold = "low"
    config.scan.max_workers = 1

    result = ScanEngine(config=config).scan_workspace(manifest)

    cross_repo = [
        finding.taint_flow
        for finding in result.findings
        if finding.taint_flow is not None
        and "/consumer/" in finding.taint_flow.source.file_path
        and "/provider/" in finding.taint_flow.sink.file_path
    ]
    assert result.taint_analysis.fidelity == "flow-field-object-call-string-sensitive-bounded"
    assert result.taint_analysis.argument_propagations >= 1
    assert result.taint_analysis.context_depth == 2
    assert result.taint_analysis.contexts_analyzed >= 2
    assert cross_repo


def test_scip_occurrence_disambiguates_cross_repo_taint_target(tmp_path: Path):
    consumer = tmp_path / "consumer"
    vulnerable_provider = tmp_path / "vulnerable-provider"
    safe_provider = tmp_path / "safe-provider"
    consumer.mkdir()
    vulnerable_provider.mkdir()
    safe_provider.mkdir()
    (consumer / "Entry.java").write_text(
        "class Entry {\n"
        '  @PostMapping("/run")\n'
        "  void run(String input) {\n"
        "    Remote remote = new Remote();\n"
        "    remote.execute(input);\n"
        "  }\n"
        "}\n"
    )
    (vulnerable_provider / "Remote.java").write_text(
        "class Remote {\n"
        "  void execute(String command) {\n"
        "    Runtime.getRuntime().exec(command);\n"
        "  }\n"
        "}\n"
    )
    (safe_provider / "OtherRemote.java").write_text(
        'class OtherRemote {\n  void execute(String ignored) { System.out.println("safe"); }\n}\n'
    )
    symbol = "scip-java maven vulnerable 1 Remote#execute(String)."
    consumer_index = tmp_path / "consumer.scip.json"
    vulnerable_index = tmp_path / "vulnerable.scip.json"
    consumer_index.write_text(
        json.dumps(
            {
                "metadata": {"toolInfo": {"name": "scip-java"}},
                "documents": [
                    {
                        "relativePath": "Entry.java",
                        "occurrences": [{"range": [4, 4, 11], "symbol": symbol}],
                        "symbols": [],
                    }
                ],
            }
        )
    )
    vulnerable_index.write_text(
        json.dumps(
            {
                "metadata": {"toolInfo": {"name": "scip-java"}},
                "documents": [
                    {
                        "relativePath": "Remote.java",
                        "occurrences": [
                            {
                                "range": [1, 7, 14],
                                "symbol": symbol,
                                "symbolRoles": 1,
                            }
                        ],
                        "symbols": [],
                    }
                ],
            }
        )
    )
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\n"
        "repositories:\n"
        "  - id: consumer\n"
        "    path: ./consumer\n"
        "    scip_index: ./consumer.scip.json\n"
        "  - id: vulnerable\n"
        "    path: ./vulnerable-provider\n"
        "    scip_index: ./vulnerable.scip.json\n"
        "  - id: safe\n"
        "    path: ./safe-provider\n"
    )
    config = AegifyConfig()
    config.llm.enabled = False
    config.rules.severity_threshold = "low"
    config.scan.max_workers = 1

    result = ScanEngine(config=config).scan_workspace(manifest)

    precise_flows = [
        finding.taint_flow
        for finding in result.findings
        if finding.taint_flow is not None
        and "/consumer/" in finding.taint_flow.source.file_path
        and "/vulnerable-provider/" in finding.taint_flow.sink.file_path
    ]
    assert precise_flows
    assert all("/safe-provider/" not in flow.sink.file_path for flow in precise_flows)
