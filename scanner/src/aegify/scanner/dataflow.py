"""Dataflow and taint analysis engine."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import networkx as nx

from aegify.graph_types import CodeGraph
from aegify.models import (
    FileAST,
    Language,
    TaintAnalysisSummary,
    TaintFlow,
    TaintPropagation,
    TaintSink,
    TaintSource,
)

logger = logging.getLogger(__name__)


@dataclass
class TaintConfig:
    """Configuration for taint sources, sinks, and sanitizers."""

    sources: dict[Language, list[SourcePattern]] = field(default_factory=dict)
    sinks: dict[Language, list[SinkPattern]] = field(default_factory=dict)
    sanitizers: dict[Language, list[str]] = field(default_factory=dict)

    @classmethod
    def default(cls) -> TaintConfig:
        config = cls(
            sources={
                Language.PYTHON: [
                    SourcePattern("request.args", "http_param"),
                    SourcePattern("request.form", "http_param"),
                    SourcePattern("request.json", "http_body"),
                    SourcePattern("request.data", "http_body"),
                    SourcePattern("request.values", "http_param"),
                    SourcePattern("request.headers", "http_header"),
                    SourcePattern("request.cookies", "http_cookie"),
                    SourcePattern("sys.argv", "cli_arg"),
                    SourcePattern("os.environ", "environment_variable"),
                    SourcePattern("os.getenv", "environment_variable"),
                    SourcePattern("input(", "stdin"),
                    SourcePattern("open(", "file_read"),
                    SourcePattern(".read(", "file_read"),
                    SourcePattern("cursor.fetchone", "database_result"),
                    SourcePattern("cursor.fetchall", "database_result"),
                    SourcePattern(".query(", "database_result"),
                    SourcePattern("configparser", "config_value"),
                    SourcePattern(".get_config", "config_value"),
                ],
                Language.JAVASCRIPT: [
                    SourcePattern("req.query", "http_param"),
                    SourcePattern("req.body", "http_body"),
                    SourcePattern("req.params", "http_param"),
                    SourcePattern("req.headers", "http_header"),
                    SourcePattern("req.cookies", "http_cookie"),
                    SourcePattern("process.argv", "cli_arg"),
                    SourcePattern("process.env", "env_var"),
                    SourcePattern("document.location", "dom"),
                    SourcePattern("window.location", "dom"),
                    SourcePattern("document.URL", "dom"),
                ],
                Language.JAVA: [
                    SourcePattern("getParameter", "http_param"),
                    SourcePattern("getHeader", "http_header"),
                    SourcePattern("getQueryString", "http_param"),
                    SourcePattern("getInputStream", "http_body"),
                    SourcePattern("getReader", "http_body"),
                    SourcePattern("getCookies", "http_cookie"),
                ],
                Language.GO: [
                    SourcePattern("r.URL.Query", "http_param"),
                    SourcePattern("r.FormValue", "http_param"),
                    SourcePattern("r.Body", "http_body"),
                    SourcePattern("r.Header", "http_header"),
                    SourcePattern("os.Args", "cli_arg"),
                    SourcePattern("os.Getenv", "env_var"),
                ],
                Language.RUST: [
                    SourcePattern("std::env::args", "cli_arg"),
                    SourcePattern("env::args", "cli_arg"),
                    SourcePattern("std::env::var", "env_var"),
                    SourcePattern("env::var", "env_var"),
                    SourcePattern("stdin", "stdin"),
                    SourcePattern("read_line", "stdin"),
                    SourcePattern("Query(", "http_param"),
                    SourcePattern("Path(", "http_param"),
                    SourcePattern("Json(", "http_body"),
                    SourcePattern("Form(", "http_param"),
                    SourcePattern("web::Query", "http_param"),
                    SourcePattern("web::Json", "http_body"),
                ],
                Language.SWIFT: [
                    SourcePattern("URLRequest", "http_param"),
                    SourcePattern("request.url", "http_param"),
                    SourcePattern("request.httpBody", "http_body"),
                    SourcePattern("UserDefaults", "user_defaults"),
                    SourcePattern("ProcessInfo.processInfo", "env_var"),
                    SourcePattern("CommandLine.arguments", "cli_arg"),
                    SourcePattern("readLine", "stdin"),
                ],
                Language.KOTLIN: [
                    SourcePattern("getParameter", "http_param"),
                    SourcePattern("getHeader", "http_header"),
                    SourcePattern("getQueryString", "http_param"),
                    SourcePattern("getInputStream", "http_body"),
                    SourcePattern("readLine", "stdin"),
                    SourcePattern("System.getenv", "env_var"),
                    SourcePattern("request.queryParams", "http_param"),
                    SourcePattern("request.body", "http_body"),
                    SourcePattern("call.receive", "http_body"),
                    SourcePattern("call.parameters", "http_param"),
                ],
            },
            sinks={
                Language.PYTHON: [
                    SinkPattern("cursor.execute", "sql_query", 0),
                    SinkPattern("session.execute", "sql_query", 0),
                    SinkPattern("db.execute", "sql_query", 0),
                    SinkPattern("os.system", "os_command", 0),
                    SinkPattern("subprocess.run", "os_command", 0),
                    SinkPattern("subprocess.call", "os_command", 0),
                    SinkPattern("subprocess.Popen", "os_command", 0),
                    SinkPattern("eval", "code_exec", 0),
                    SinkPattern("exec", "code_exec", 0),
                    SinkPattern("open", "file_access", 0),
                    SinkPattern("render_template_string", "xss", 0),
                    SinkPattern("Markup", "xss", 0),
                    SinkPattern("pickle.loads", "deserialization", 0),
                    SinkPattern("yaml.load", "deserialization", 0),
                    SinkPattern("marshal.loads", "deserialization", 0),
                    SinkPattern("jsonpickle.decode", "deserialization", 0),
                    SinkPattern("ldap.search", "ldap_query", 0),
                    SinkPattern("ldap.filter_format", "ldap_query", 0),
                    SinkPattern("etree.fromstring", "xml_parse", 0),
                    SinkPattern("etree.parse", "xml_parse", 0),
                    SinkPattern("minidom.parseString", "xml_parse", 0),
                    SinkPattern("requests.get", "ssrf", 0),
                    SinkPattern("requests.post", "ssrf", 0),
                    SinkPattern("urllib.request.urlopen", "ssrf", 0),
                    SinkPattern("httpx.get", "ssrf", 0),
                    SinkPattern("redirect", "redirect", 0),
                    SinkPattern("logging.info", "log_injection", 0),
                    SinkPattern("logger.info", "log_injection", 0),
                    SinkPattern("logger.warning", "log_injection", 0),
                    SinkPattern("render_template", "template_render", 0),
                    SinkPattern("Jinja2", "template_render", 0),
                    SinkPattern("os.chmod", "file_permission", 0),
                    SinkPattern("hashlib.md5", "crypto_operation", 0),
                    SinkPattern("hashlib.sha1", "crypto_operation", 0),
                    SinkPattern("DES", "crypto_operation", 0),
                ],
                Language.JAVASCRIPT: [
                    SinkPattern("query", "sql_query", 0),
                    SinkPattern("execute", "sql_query", 0),
                    SinkPattern("exec", "os_command", 0),
                    SinkPattern("execSync", "os_command", 0),
                    SinkPattern("spawn", "os_command", 0),
                    SinkPattern("eval", "code_exec", 0),
                    SinkPattern("Function", "code_exec", 0),
                    SinkPattern("innerHTML", "xss", 0),
                    SinkPattern("dangerouslySetInnerHTML", "xss", 0),
                    SinkPattern("document.write", "xss", 0),
                    SinkPattern("fs.readFile", "file_access", 0),
                    SinkPattern("fs.writeFile", "file_access", 0),
                    SinkPattern("JSON.parse", "deserialization", 0),
                    SinkPattern("deserialize", "deserialization", 0),
                    SinkPattern("node-serialize", "deserialization", 0),
                    SinkPattern("fetch", "ssrf", 0),
                    SinkPattern("axios.get", "ssrf", 0),
                    SinkPattern("axios.post", "ssrf", 0),
                    SinkPattern("http.get", "ssrf", 0),
                    SinkPattern("res.redirect", "redirect", 0),
                    SinkPattern("location.href", "redirect", 0),
                    SinkPattern("console.log", "log_injection", 0),
                    SinkPattern("xml2js.parseString", "xml_parse", 0),
                    SinkPattern("DOMParser", "xml_parse", 0),
                    SinkPattern("createCipher", "crypto_operation", 0),
                    SinkPattern("createHash", "crypto_operation", 0),
                ],
                Language.JAVA: [
                    SinkPattern("executeQuery", "sql_query", 0),
                    SinkPattern("executeUpdate", "sql_query", 0),
                    SinkPattern("createQuery", "sql_query", 0),
                    SinkPattern("Runtime.exec", "os_command", 0),
                    SinkPattern("ProcessBuilder", "os_command", 0),
                ],
                Language.GO: [
                    SinkPattern("db.Query", "sql_query", 0),
                    SinkPattern("db.Exec", "sql_query", 0),
                    SinkPattern("exec.Command", "os_command", 0),
                    SinkPattern("template.HTML", "xss", 0),
                    SinkPattern("fmt.Fprintf", "xss", 0),
                ],
                Language.RUST: [
                    SinkPattern("execute", "sql_query", 0),
                    SinkPattern("query", "sql_query", 0),
                    SinkPattern("query_as", "sql_query", 0),
                    SinkPattern("Command::new", "os_command", 0),
                    SinkPattern("Command.arg", "os_command", 0),
                    SinkPattern("process::Command", "os_command", 0),
                    SinkPattern("write!", "xss", 0),
                    SinkPattern("format!", "string_format", 0),
                ],
                Language.SWIFT: [
                    SinkPattern("execute", "sql_query", 0),
                    SinkPattern("prepare", "sql_query", 0),
                    SinkPattern("Process", "os_command", 0),
                    SinkPattern("launchedProcess", "os_command", 0),
                    SinkPattern("NSTask", "os_command", 0),
                    SinkPattern("evaluateJavaScript", "code_exec", 0),
                    SinkPattern("FileManager", "file_access", 0),
                ],
                Language.KOTLIN: [
                    SinkPattern("executeQuery", "sql_query", 0),
                    SinkPattern("executeUpdate", "sql_query", 0),
                    SinkPattern("createStatement", "sql_query", 0),
                    SinkPattern("rawQuery", "sql_query", 0),
                    SinkPattern("Runtime.exec", "os_command", 0),
                    SinkPattern("exec", "os_command", 0),
                    SinkPattern("ProcessBuilder", "os_command", 0),
                    SinkPattern("evaluateJavascript", "code_exec", 0),
                ],
            },
            sanitizers={
                Language.PYTHON: [
                    "html.escape",
                    "bleach.clean",
                    "shlex.quote",
                    "markupsafe.escape",
                    "escape",
                    "sanitize",
                    "validate",
                    "parameterized",
                    "prepare",
                ],
                Language.JAVASCRIPT: [
                    "DOMPurify.sanitize",
                    "escape",
                    "encodeURIComponent",
                    "encodeURI",
                    "sanitize",
                    "validator",
                    "xss",
                    "parameterized",
                    "prepare",
                ],
                Language.JAVA: [
                    "PreparedStatement",
                    "setString",
                    "ESAPI.encoder",
                    "StringEscapeUtils",
                    "HtmlUtils.htmlEscape",
                    "sanitize",
                ],
                Language.GO: [
                    "html.EscapeString",
                    "template.HTMLEscapeString",
                    "url.QueryEscape",
                    "Prepare",
                    "sanitize",
                ],
                Language.RUST: [
                    "html_escape",
                    "encode",
                    "sanitize",
                    "validate",
                    "bind",
                    "prepare",
                    "parameterized",
                ],
                Language.SWIFT: [
                    "addingPercentEncoding",
                    "replacingOccurrences",
                    "sanitize",
                    "validate",
                    "escape",
                    "prepare",
                ],
                Language.KOTLIN: [
                    "PreparedStatement",
                    "setString",
                    "prepareStatement",
                    "HtmlCompat.fromHtml",
                    "TextUtils.htmlEncode",
                    "sanitize",
                    "validate",
                    "escape",
                ],
            },
        )
        # TypeScript shares the JavaScript runtime/API model.  Keeping an
        # explicit language entry avoids silently disabling taint when the
        # parser reports ``Language.TYPESCRIPT`` for .ts/.tsx sources.
        config.sources[Language.TYPESCRIPT] = list(config.sources[Language.JAVASCRIPT])
        config.sinks[Language.TYPESCRIPT] = list(config.sinks[Language.JAVASCRIPT])
        config.sanitizers[Language.TYPESCRIPT] = list(config.sanitizers[Language.JAVASCRIPT])
        return config


@dataclass
class SourcePattern:
    pattern: str
    source_type: str


@dataclass
class SinkPattern:
    pattern: str
    sink_type: str
    argument_index: int = 0


class DataflowAnalyzer:
    """Performs taint analysis tracking data from sources to sinks."""

    def __init__(self, config: TaintConfig | None = None) -> None:
        self.config = config or TaintConfig.default()
        self.summary = TaintAnalysisSummary()

    def analyze(
        self,
        file_asts: list[FileAST],
        call_graph: CodeGraph,
        program_graph: object | None = None,
    ) -> list[TaintFlow]:
        """Run bounded global taint analysis across files and repositories."""
        if program_graph is None:
            from aegify.ir import ProgramGraphBuilder

            program_graph = ProgramGraphBuilder().build(file_asts).graph

        from aegify.scanner.taint_v2 import StructuredTaintAnalyzer

        analyzer = StructuredTaintAnalyzer(self.config)
        flows, self.summary = analyzer.analyze(
            file_asts,
            call_graph,
            program_graph,
        )
        logger.info(
            "Found %d global taint flows in %d iterations",
            len(flows),
            self.summary.iterations,
        )
        return flows

    def _find_sources(self, ast: FileAST) -> list[TaintSource]:
        """Find taint sources in a file."""
        sources: list[TaintSource] = []
        patterns = self.config.sources.get(ast.language, [])

        for call in ast.calls:
            for pattern in patterns:
                call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
                if pattern.pattern in call_text:
                    sources.append(
                        TaintSource(
                            variable=call_text,
                            file_path=ast.file_path,
                            line=call.line,
                            source_type=pattern.source_type,
                            in_function=call.in_function,
                        )
                    )
                    break

            # Also check arguments for source patterns
            for arg in call.arguments:
                for pattern in patterns:
                    if pattern.pattern in arg:
                        sources.append(
                            TaintSource(
                                variable=arg,
                                file_path=ast.file_path,
                                line=call.line,
                                source_type=pattern.source_type,
                                in_function=call.in_function,
                            )
                        )
                        break

        return sources

    def _find_sinks(self, ast: FileAST) -> list[TaintSink]:
        """Find taint sinks in a file."""
        sinks: list[TaintSink] = []
        patterns = self.config.sinks.get(ast.language, [])

        for call in ast.calls:
            call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
            for pattern in patterns:
                if pattern.pattern in call_text:
                    sinks.append(
                        TaintSink(
                            function=call_text,
                            file_path=ast.file_path,
                            line=call.line,
                            sink_type=pattern.sink_type,
                            argument_index=pattern.argument_index,
                            in_function=call.in_function,
                        )
                    )
                    break

        return sinks

    def _trace_flows(
        self,
        ast: FileAST,
        sources: list[TaintSource],
        sinks: list[TaintSink],
        call_graph: CodeGraph,
    ) -> list[TaintFlow]:
        """Trace taint flows from sources to sinks."""
        flows: list[TaintFlow] = []

        for source in sources:
            for sink in sinks:
                # Check if source and sink are in the same function scope
                # or connected via call graph
                if self._can_reach(source, sink, ast, call_graph):
                    sanitized, sanitizer = self._check_sanitization(source, sink, ast)
                    path = self._build_propagation_path(source, sink, ast)

                    flows.append(
                        TaintFlow(
                            source=source,
                            sink=sink,
                            path=path,
                            sanitized=sanitized,
                            sanitizer=sanitizer,
                        )
                    )

        return flows

    def _can_reach(
        self,
        source: TaintSource,
        sink: TaintSink,
        ast: FileAST,
        call_graph: CodeGraph,
    ) -> bool:
        """Check if tainted data can flow from source to sink."""
        # Same function scope: direct flow possible
        if source.in_function == sink.in_function and source.line < sink.line:
            return True

        # Cross-function: check call graph connectivity
        if source.in_function and sink.in_function:
            source_node = self._resolve_scope_node(call_graph, source.file_path, source.in_function)
            sink_node = self._resolve_scope_node(call_graph, sink.file_path, sink.in_function)
            if source_node is None or sink_node is None:
                return False
            try:
                return nx.has_path(call_graph, source_node, sink_node)
            except nx.NodeNotFound:
                pass

        # Source at module level can reach anything
        if source.in_function is None:
            return True

        return False

    @staticmethod
    def _resolve_scope_node(
        call_graph: CodeGraph,
        file_path: str,
        scope_name: str,
    ) -> str | None:
        """Resolve a parser scope name to a collision-safe graph node.

        Workspace graphs intentionally use repository-qualified symbol IDs, so
        querying them with a short method name would silently lose all
        cross-function flows. File identity plus the language-native qualified
        name gives a deterministic mapping without guessing across repositories.
        """
        if scope_name in call_graph:
            return scope_name

        matches: list[str] = []
        for node_id, attributes in call_graph.nodes(data=True):
            node = attributes.get("data") if attributes else None
            if node is None or node.file_path != file_path:
                continue
            qualified_name = node.qualified_name
            if qualified_name == scope_name or qualified_name.endswith(f".{scope_name}"):
                matches.append(node_id)

        return matches[0] if len(matches) == 1 else None

    def _check_sanitization(
        self,
        source: TaintSource,
        sink: TaintSink,
        ast: FileAST,
    ) -> tuple[bool, str | None]:
        """Check if the flow is sanitized between source and sink."""
        sanitizers = self.config.sanitizers.get(ast.language, [])

        for call in ast.calls:
            # Check calls between source and sink lines
            if not (source.line <= call.line <= sink.line):
                continue

            # Check if call is in the same function scope
            if source.in_function and call.in_function != source.in_function:
                if sink.in_function and call.in_function != sink.in_function:
                    continue

            call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
            for sanitizer in sanitizers:
                if sanitizer.lower() in call_text.lower():
                    return True, call_text

        # Check for parameterized queries (special case for SQL sinks)
        if sink.sink_type == "sql_query":
            for call in ast.calls:
                if call.line == sink.line:
                    for arg in call.arguments:
                        if "%" not in arg and "+" not in arg and "f'" not in arg:
                            # Likely using parameterized query if not string concat/format
                            if "?" in arg or "%s" in arg or "$" in arg:
                                return True, "parameterized_query"

        return False, None

    def _build_propagation_path(
        self,
        source: TaintSource,
        sink: TaintSink,
        ast: FileAST,
    ) -> list[TaintPropagation]:
        """Build a simplified propagation path from source to sink."""
        path: list[TaintPropagation] = []

        path.append(
            TaintPropagation(
                variable=source.variable,
                file_path=source.file_path,
                line=source.line,
                propagation_type="source",
                function=source.in_function,
            )
        )

        # Find intermediate assignments/calls between source and sink
        for call in ast.calls:
            if source.line < call.line < sink.line:
                if call.in_function == source.in_function or call.in_function == sink.in_function:
                    call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
                    path.append(
                        TaintPropagation(
                            variable=call_text,
                            file_path=call.file_path,
                            line=call.line,
                            propagation_type="call",
                            function=call.in_function,
                        )
                    )

        path.append(
            TaintPropagation(
                variable=sink.function,
                file_path=sink.file_path,
                line=sink.line,
                propagation_type="sink",
                function=sink.in_function,
            )
        )

        return path
