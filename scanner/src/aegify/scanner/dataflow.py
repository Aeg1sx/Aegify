"""Dataflow and taint analysis engine."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import networkx as nx

from aegify.config import TaintAnalysisConfig
from aegify.graph_types import CodeGraph
from aegify.models import (
    CallSite,
    FileAST,
    Language,
    PythonFileAccess,
    TaintAnalysisSummary,
    TaintFlow,
    TaintPropagation,
    TaintSink,
    TaintSource,
)
from aegify.scanner.python_code import code_operand
from aegify.scanner.python_deserialization import sink_operand
from aegify.scanner.python_ldap import LDAPConnections
from aegify.scanner.python_process import process_input
from aegify.scanner.python_redirect import redirect_operand
from aegify.scanner.python_regex import regex_operand
from aegify.scanner.python_requests import body_accesses
from aegify.scanner.python_scope import PythonModules

logger = logging.getLogger(__name__)


@dataclass
class TaintConfig:
    """Configuration for taint sources, sinks, and sanitizers."""

    sources: dict[Language, list[SourcePattern]] = field(default_factory=dict)
    sinks: dict[Language, list[SinkPattern]] = field(default_factory=dict)
    sanitizers: dict[Language, list[str]] = field(default_factory=dict)

    def source_patterns_for(self, file: FileAST) -> list[SourcePattern]:
        patterns = self.sources.get(file.language, [])
        if file.python_request_body_reads is None:
            return patterns
        return [p for p in patterns if not p.python_request_body]

    def request_body_sources(self, file: FileAST) -> list[TaintSource]:
        if not file.python_request_body_reads:
            return []
        patterns = {p.pattern for p in self.sources.get(file.language, []) if p.python_request_body}
        functions = {fn.line_start: fn.qualified_name for fn in file.functions}
        return [
            TaintSource(
                variable=read.expression,
                file_path=file.file_path,
                line=read.line,
                source_type="http_body",
                in_function=functions.get(read.function_line),
            )
            for read in file.python_request_body_reads
            if read.pattern in patterns
        ]

    @classmethod
    def default(cls) -> TaintConfig:
        config = cls(
            sources={
                Language.PYTHON: [
                    SourcePattern("request.args", "http_param"),
                    SourcePattern("request.form", "http_param"),
                    SourcePattern("request.GET", "http_param"),
                    SourcePattern("request.POST", "http_param"),
                    SourcePattern("request.json", "http_body"),
                    SourcePattern("request.data", "http_body"),
                    SourcePattern("request.values", "http_param"),
                    SourcePattern("request.query_string", "http_query"),
                    SourcePattern("request.headers", "http_header"),
                    SourcePattern("request.cookies", "http_cookie"),
                    SourcePattern("sys.argv", "cli_arg"),
                    SourcePattern("os.environ", "environment_variable"),
                    SourcePattern("os.getenv", "environment_variable"),
                    SourcePattern("builtins.input", "stdin", resolved_only=True),
                    SourcePattern("python.file_open", "file_read", resolved_only=True),
                    SourcePattern(".read(", "file_read"),
                    SourcePattern("cursor.fetchone", "database_result"),
                    SourcePattern("cursor.fetchall", "database_result"),
                    SourcePattern(".query(", "database_result"),
                    SourcePattern("configparser.file_value", "config_value", resolved_only=True),
                    SourcePattern(".get_config", "config_value"),
                    SourcePattern("requests.get", "external_api_response"),
                    SourcePattern("requests.post", "external_api_response"),
                    SourcePattern("httpx.get", "external_api_response"),
                    SourcePattern("httpx.post", "external_api_response"),
                    SourcePattern("urllib.request.urlopen", "external_api_response"),
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
                    SourcePattern("fetch", "external_api_response"),
                    SourcePattern("axios.get", "external_api_response"),
                    SourcePattern("axios.post", "external_api_response"),
                    SourcePattern("http.get", "external_api_response"),
                ],
                Language.JAVA: [
                    SourcePattern("getParameter", "http_param"),
                    SourcePattern("getHeader", "http_header"),
                    SourcePattern("getQueryString", "http_param"),
                    SourcePattern("getInputStream", "http_body"),
                    SourcePattern("getReader", "http_body"),
                    SourcePattern("getCookies", "http_cookie"),
                    SourcePattern("HttpClient.send", "external_api_response"),
                    SourcePattern("RestTemplate.getForEntity", "external_api_response"),
                    SourcePattern("RestTemplate.exchange", "external_api_response"),
                    SourcePattern("WebClient.retrieve", "external_api_response"),
                ],
                Language.GO: [
                    SourcePattern("r.URL.Query", "http_param"),
                    SourcePattern("r.FormValue", "http_param"),
                    SourcePattern("r.Body", "http_body"),
                    SourcePattern("r.Header", "http_header"),
                    SourcePattern("os.Args", "cli_arg"),
                    SourcePattern("os.Getenv", "env_var"),
                    SourcePattern("http.Get", "external_api_response"),
                    SourcePattern("http.Post", "external_api_response"),
                    SourcePattern("http.Client.Do", "external_api_response"),
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
                    SourcePattern("HttpClient.send", "external_api_response"),
                    SourcePattern("RestTemplate.getForEntity", "external_api_response"),
                    SourcePattern("RestTemplate.exchange", "external_api_response"),
                    SourcePattern("WebClient.retrieve", "external_api_response"),
                ],
            },
            sinks={
                Language.PYTHON: [
                    SinkPattern("cursor.execute", "sql_query", 0),
                    SinkPattern("session.execute", "sql_query", 0),
                    SinkPattern("db.execute", "sql_query", 0),
                    SinkPattern("os.system", "os_command", 0),
                    SinkPattern("python.subprocess", "os_command", python_process=True),
                    SinkPattern("python.dynamic_code", "code_exec", python_code=True),
                    SinkPattern("python.filesystem", "file_access", python_files=True),
                    SinkPattern("python.template", "template_source", python_template=True),
                    SinkPattern("render_template_string", "xss", 0),
                    SinkPattern("Markup", "xss", 0),
                    SinkPattern(
                        "python.deserialization", "deserialization", python_deserialization=True
                    ),
                    SinkPattern("marshal.loads", "deserialization", 0),
                    SinkPattern("jsonpickle.decode", "deserialization", 0),
                    SinkPattern("python.ldap.search", "ldap_search_filter", python_ldap=True),
                    SinkPattern("etree.fromstring", "xml_parse", 0),
                    SinkPattern("etree.parse", "xml_parse", 0),
                    SinkPattern("requests.get", "ssrf", 0),
                    SinkPattern("requests.post", "ssrf", 0),
                    SinkPattern("urllib.request.urlopen", "ssrf", 0),
                    SinkPattern("python.download", "ssrf", python_download=True),
                    SinkPattern("httpx.get", "ssrf", 0),
                    SinkPattern("python.http.redirect", "redirect", python_redirect=True),
                    SinkPattern("logging.info", "log_injection", 0),
                    SinkPattern("logger.info", "log_injection", 0),
                    SinkPattern("logger.warning", "log_injection", 0),
                    SinkPattern("render_template", "template_render", 0),
                    SinkPattern("Jinja2", "template_render", 0),
                    SinkPattern("os.chmod", "file_permission", 0),
                    SinkPattern("hashlib.md5", "crypto_operation", 0),
                    SinkPattern("hashlib.sha1", "crypto_operation", 0),
                    SinkPattern("DES", "crypto_operation", 0),
                    SinkPattern("python.regex", "regex_compile", python_regex=True),
                    # A negative index denotes the receiver expression. For
                    # ``template.format(value)``, the receiver is the format
                    # program and the arguments are only substitution data.
                    SinkPattern(".format", "string_format", -1),
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
                    SinkPattern("RegExp", "regex_compile", 0),
                ],
                Language.JAVA: [
                    SinkPattern("executeQuery", "sql_query", 0),
                    SinkPattern("executeUpdate", "sql_query", 0),
                    SinkPattern("createQuery", "sql_query", 0),
                    SinkPattern("Runtime.exec", "os_command", 0),
                    SinkPattern("ProcessBuilder", "os_command", 0),
                    SinkPattern("Pattern.compile", "regex_compile", 0),
                ],
                Language.GO: [
                    SinkPattern("db.Query", "sql_query", 0),
                    SinkPattern("db.Exec", "sql_query", 0),
                    SinkPattern("exec.Command", "os_command", 0),
                    SinkPattern("template.HTML", "xss", 0),
                    SinkPattern("fmt.Fprintf", "xss", 0),
                    SinkPattern("regexp.Compile", "regex_compile", 0),
                    SinkPattern("regexp.MustCompile", "regex_compile", 0),
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
                    SinkPattern("Pattern.compile", "regex_compile", 0),
                ],
            },
            sanitizers={
                Language.PYTHON: [
                    "html.escape",
                    "bleach.clean",
                    "shlex.quote",
                    "markupsafe.escape",
                    "validate_path",
                    "validate_command",
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
    resolved_only: bool = False

    @property
    def python_request_body(self) -> bool:
        return self.source_type == "http_body" and self.pattern in {"request.json", "request.data"}

    def accepts_source_text(self, file: FileAST, expression: str) -> bool:
        # Older serialized ASTs have calls but no framework binding facts.
        if file.language == Language.PYTHON and self.python_request_body:
            return self.pattern in body_accesses(expression)
        return True

    def resolved_call(self, call: CallSite, file: FileAST) -> bool:
        if self.pattern == "python.file_open":
            if call.python_file_access:
                return call.python_file_access.api in {
                    "open",
                    "builtins.open",
                    "io.open",
                    "codecs.open",
                    "os.open",
                    "pathlib.Path.open",
                }
            # Older snapshots can still identify a real call to a named standard API.
            return (
                not file.python_file_access_resolved
                and call.callee == "open"
                and (call.receiver in (None, "builtins", "io", "codecs", "os"))
            )
        if self.pattern == "builtins.input" and not file.python_stdin_resolved:
            # Pre-binding ASTs still identify an actual call, never a word in a literal.
            return call.callee == "input" and call.receiver in (None, "builtins")
        return call.resolved_source == self.pattern


@dataclass
class SinkPattern:
    pattern: str
    sink_type: str
    argument_index: int = 0
    exact: bool = False
    python_files: bool = False
    python_deserialization: bool = False
    python_ldap: bool = False
    python_redirect: bool = False
    python_code: bool = False
    python_process: bool = False
    python_template: bool = False
    python_download: bool = False
    python_regex: bool = False

    def accepts_receiver(self, call: CallSite, language: Language) -> bool:
        if self.pattern == "RegExp" and self.sink_type == "regex_compile":
            return (
                call.receiver is None
                if call.javascript_regex_pattern is None
                else call.javascript_regex_pattern
            )
        return not (
            self.sink_type == "os_command"
            and self.pattern == "exec"
            and language in (Language.JAVASCRIPT, Language.TYPESCRIPT)
            and call.receiver_type == "RegExp"
        )

    @property
    def has_python_operand(self) -> bool:
        return (
            self.python_code
            or self.python_template
            or self.python_download
            or self.python_regex
            or self.python_process
            or self.python_ldap
            or self.python_redirect
            or self.python_deserialization
        )

    def select_operand(
        self, call: CallSite, file: FileAST, modules: PythonModules, ldap: LDAPConnections
    ) -> tuple[str, int] | None:
        if self.python_template or self.python_download:
            operand = (
                call.python_template_source if self.python_template else call.python_download_url
            )
            if operand and modules.external(file, operand.api):
                return operand.api, operand.argument_index
            return None
        if self.python_process:
            process = process_input(call, file, modules)
            return (
                (process.api, process.argument_index)
                if process and process.argument_index is not None
                else None
            )
        if self.python_regex:
            return regex_operand(call, file, modules)
        if self.python_code:
            return code_operand(call, file, modules)
        if self.python_ldap:
            return ldap.operand(call, file)
        if self.python_redirect:
            return redirect_operand(call, file, modules)
        return sink_operand(call, file) if self.python_deserialization else None

    @staticmethod
    def file_operation(call: CallSite, file_ast: FileAST) -> PythonFileAccess | None:
        if file_ast.python_file_access_resolved or call.python_file_access:
            return call.python_file_access
        # Older serialized ASTs predate import-aware path selection.
        name = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
        if name in {"open", "builtins.open", "io.open"}:
            return PythonFileAccess(api=name, path_indices=[0])
        return None


class DataflowAnalyzer:
    """Performs taint analysis tracking data from sources to sinks."""

    def __init__(
        self, config: TaintConfig | None = None, *, limits: TaintAnalysisConfig | None = None
    ) -> None:
        self.config = config or TaintConfig.default()
        self.limits = limits or TaintAnalysisConfig()
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

        analyzer = StructuredTaintAnalyzer(
            self.config,
            max_iterations=self.limits.max_iterations,
            context_depth=self.limits.context_depth,
            max_contexts=self.limits.max_contexts,
        )
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
        sources = self.config.request_body_sources(ast)
        patterns = self.config.source_patterns_for(ast)

        for call in ast.calls:
            for pattern in patterns:
                call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
                if (
                    pattern.resolved_call(call, ast)
                    if pattern.resolved_only
                    else pattern.pattern in call_text
                    and pattern.accepts_source_text(ast, call_text)
                ):
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
                    if (
                        not pattern.resolved_only
                        and pattern.pattern in arg
                        and pattern.accepts_source_text(ast, arg)
                    ):
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
        modules = PythonModules([ast])
        ldap = LDAPConnections([ast], modules)
        sinks: list[TaintSink] = []
        patterns = self.config.sinks.get(ast.language, [])

        for call in ast.calls:
            call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
            for pattern in patterns:
                if not pattern.accepts_receiver(call, ast.language):
                    continue
                if pattern.has_python_operand:
                    selected = pattern.select_operand(call, ast, modules, ldap)
                    if selected:
                        sinks.append(
                            TaintSink(
                                function=selected[0],
                                argument_index=selected[1],
                                file_path=ast.file_path,
                                line=call.line,
                                sink_type=pattern.sink_type,
                                in_function=call.in_function,
                            )
                        )
                        break
                    continue
                if pattern.python_files:
                    if operation := pattern.file_operation(call, ast):
                        sinks.extend(
                            TaintSink(
                                function=operation.api,
                                file_path=ast.file_path,
                                line=call.line,
                                sink_type=operation.sink_type,
                                argument_index=index,
                                in_function=call.in_function,
                            )
                            for index in operation.path_indices
                        )
                        break
                    continue
                matches = (
                    call_text == pattern.pattern
                    if pattern.exact
                    else self._sink_pattern_matches(call_text, call.callee, pattern.pattern)
                )
                if matches:
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

    @staticmethod
    def _sink_pattern_matches(call_text: str, callee: str, pattern: str) -> bool:
        """Match sink names on call boundaries instead of arbitrary substrings."""
        if pattern.startswith("."):
            return call_text.endswith(pattern)
        if "." in pattern:
            receiver_pattern, method_pattern = pattern.rsplit(".", 1)
            receiver = call_text[: -(len(callee) + 1)] if call_text.endswith(callee) else ""
            return callee == method_pattern and bool(
                re.search(
                    rf"(?<![A-Za-z0-9_$]){re.escape(receiver_pattern)}"
                    r"(?![A-Za-z0-9_$])",
                    receiver,
                )
            )
        if "::" in pattern:
            return call_text == pattern or call_text.endswith(f".{pattern}")
        return callee == pattern or call_text == pattern

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
