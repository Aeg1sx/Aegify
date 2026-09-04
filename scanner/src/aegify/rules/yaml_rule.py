"""YAML-based custom rule loader and evaluator."""

from __future__ import annotations

import logging
import math
import re
from pathlib import Path
from typing import Any

import yaml

from aegify.graph_types import CodeGraph
from aegify.models import (
    EvidenceState,
    FileAST,
    Finding,
    FindingDisposition,
    Language,
    Severity,
    TaintFlow,
)
from aegify.rules.base import RuleDefinition, SecurityRule, register_rule

logger = logging.getLogger(__name__)

_FIXED_HTTP_ORIGIN_RE = re.compile(
    r"""(?ix)
    ^\s*[rubf]*[\"'`]
    https?://
    (?:\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)
    (?::\d{1,5})?
    [/?#]
    """
)

# Map string language names to Language enum
LANG_MAP: dict[str, Language] = {
    "python": Language.PYTHON,
    "javascript": Language.JAVASCRIPT,
    "typescript": Language.TYPESCRIPT,
    "java": Language.JAVA,
    "go": Language.GO,
    "rust": Language.RUST,
    "swift": Language.SWIFT,
    "kotlin": Language.KOTLIN,
}

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class YAMLRule(SecurityRule):
    """A security rule loaded from a YAML definition."""

    def __init__(self, definition: RuleDefinition, spec: YAMLRuleSpec, raw_yaml: str = "") -> None:
        self.definition = definition
        self.spec = spec
        self.raw_yaml = raw_yaml

    def evaluate(
        self,
        file_asts: list[FileAST],
        call_graph: CodeGraph,
        taint_flows: list[TaintFlow],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Taint-based detection
        if self.spec.taint:
            findings.extend(self._eval_taint(taint_flows, file_asts))

        # Pattern-based detection
        if self.spec.patterns:
            findings.extend(self._eval_patterns(file_asts))

        # Structured semantic detection. Broad lexical fallbacks for the same
        # rule may remain advisory while this evidence is CI-blocking.
        if self.spec.semantic:
            findings.extend(self._eval_semantic(file_asts))

        return findings

    def _eval_semantic(self, file_asts: list[FileAST]) -> list[Finding]:
        """Evaluate normalized same-function semantic evidence."""
        semantic = self.spec.semantic
        if semantic is None or semantic.kind != "database_race":
            return []

        findings: list[Finding] = []
        for ast in file_asts:
            if self.definition.languages and ast.language not in self.definition.languages:
                continue
            try:
                source_lines = Path(ast.file_path).read_text(errors="replace").splitlines()
            except OSError:
                continue

            seen_functions: set[tuple[int, int]] = set()
            for function in ast.functions:
                bounds = (function.line_start, function.line_end)
                if bounds in seen_functions:
                    continue
                seen_functions.add(bounds)
                function_source = "\n".join(
                    source_lines[max(function.line_start - 1, 0) : function.line_end]
                )
                if semantic._defense_re.search(function_source):
                    continue

                calls = sorted(
                    (
                        call
                        for call in ast.calls
                        if function.line_start <= call.line <= function.line_end
                        and call.receiver
                        and semantic._receiver_re.search(call.receiver)
                    ),
                    key=lambda call: (call.line, call.column),
                )
                reads = [call for call in calls if semantic._read_callee_re.fullmatch(call.callee)]
                writes = [
                    call for call in calls if semantic._write_callee_re.fullmatch(call.callee)
                ]
                matched = False
                for read in reads:
                    for write in writes:
                        if write.line <= read.line:
                            continue
                        if write.line - read.line > semantic.max_lines_between:
                            continue
                        if semantic.same_receiver and write.receiver != read.receiver:
                            continue
                        segment = "\n".join(source_lines[read.line - 1 : write.line])
                        if not semantic._required_between_re.search(segment):
                            continue
                        message = self._safe_format(
                            self.spec.message,
                            source=f"{read.receiver}.{read.callee}",
                            source_line=read.line,
                            sink=f"{write.receiver}.{write.callee}",
                            sink_line=write.line,
                            source_type="database_read",
                            sink_type="database_write",
                            line=write.line,
                            file=ast.file_path,
                        )
                        findings.append(
                            self._create_finding(
                                file_path=ast.file_path,
                                line_start=write.line,
                                line_end=write.line,
                                code_snippet=segment,
                                message=message,
                                evidence_state=EvidenceState.REACHABLE,
                                disposition=FindingDisposition.BLOCKING,
                            )
                        )
                        matched = True
                        break
                    if matched:
                        break
                if len(findings) >= self._MAX_FINDINGS_PER_FILE:
                    break
        return findings

    def _eval_taint(self, taint_flows: list[TaintFlow], file_asts: list[FileAST]) -> list[Finding]:
        """Evaluate taint-based rules."""
        findings: list[Finding] = []
        taint = self.spec.taint
        if not taint:
            return findings

        # Build file_path -> FileAST index for O(1) lookup (replaces O(n) linear scan)
        fp_index: dict[str, FileAST] = {a.file_path: a for a in file_asts}

        # Use pre-built sets for O(1) lookup
        sink_types = taint._sink_types_set
        source_types = taint._source_types_set

        # Pre-build language set for fast membership test
        rule_languages = set(self.definition.languages) if self.definition.languages else None

        for flow in taint_flows:
            # Filter by sink type (O(1) set lookup)
            if sink_types and flow.sink.sink_type not in sink_types:
                continue

            # Filter by source type (O(1) set lookup)
            if source_types and flow.source.source_type not in source_types:
                continue

            # Skip sanitized flows
            if flow.sanitized and not taint.ignore_sanitizers:
                continue

            # Filter by language using O(1) index lookup
            if rule_languages:
                file_ast = fp_index.get(flow.sink.file_path)
                if file_ast is None or file_ast.language not in rule_languages:
                    continue

            # Check sink function pattern (pre-compiled regex)
            if taint._sink_pattern_re:
                if not taint._sink_pattern_re.search(flow.sink.function):
                    continue

            # Check source pattern (pre-compiled regex)
            if taint._source_pattern_re:
                if not taint._source_pattern_re.search(flow.source.variable):
                    continue

            # A tainted path or query component on a statically fixed HTTP(S)
            # origin is not, by itself, SSRF. Keep authority-controlled URLs
            # blocking, but do not turn ordinary REST resource identifiers
            # into CWE-918 findings merely because they reach fetch().
            if self.definition.cwe_id == 918 and self._has_fixed_http_origin(flow, fp_index):
                continue

            findings.append(
                self._create_finding(
                    file_path=flow.sink.file_path,
                    line_start=flow.sink.line,
                    line_end=flow.sink.line,
                    code_snippet="",
                    message=self._safe_format(
                        self.spec.message,
                        source=flow.source.variable,
                        source_line=flow.source.line,
                        sink=flow.sink.function,
                        sink_line=flow.sink.line,
                        source_type=flow.source.source_type,
                        sink_type=flow.sink.sink_type,
                        line=flow.sink.line,
                        file=flow.sink.file_path,
                    ),
                    taint_flow=flow,
                    evidence_state=EvidenceState.REACHABLE,
                    disposition=FindingDisposition.BLOCKING,
                )
            )

        return findings

    @staticmethod
    def _has_fixed_http_origin(flow: TaintFlow, fp_index: dict[str, FileAST]) -> bool:
        """Return true when every matching sink on the line has a literal origin."""
        ast = fp_index.get(flow.sink.file_path)
        if ast is None or flow.sink.argument_index < 0:
            return False

        matching_calls = []
        for call in ast.calls:
            call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
            if call.line == flow.sink.line and call_text == flow.sink.function:
                matching_calls.append(call)
        if not matching_calls:
            return False

        argument_index = flow.sink.argument_index
        return all(
            len(call.arguments) > argument_index
            and _FIXED_HTTP_ORIGIN_RE.match(call.arguments[argument_index]) is not None
            for call in matching_calls
        )

    @staticmethod
    def _safe_format(template: str, **kwargs: Any) -> str:
        """Format message template, gracefully handling missing keys and brace literals."""
        try:
            return template.format(**kwargs)
        except KeyError, ValueError, IndexError:
            # Fallback: replace known placeholders manually
            result = template
            for key, val in kwargs.items():
                result = result.replace(f"{{{key}}}", str(val))
            return result

    # Maximum findings per rule per file to prevent explosion from broad patterns
    _MAX_FINDINGS_PER_FILE = 5
    # Regex patterns are noisier (secrets, logging), use a tighter cap
    _MAX_REGEX_FINDINGS_PER_FILE = 2

    def _eval_patterns(self, file_asts: list[FileAST]) -> list[Finding]:
        """Evaluate call and source pattern rules against parsed files."""
        findings: list[Finding] = []

        for ast in file_asts:
            # Filter by language
            if self.definition.languages and ast.language not in self.definition.languages:
                continue

            file_findings: list[Finding] = []
            source: str | None = None
            cap = self._MAX_FINDINGS_PER_FILE

            for pattern_spec in self.spec.patterns:
                # Skip empty patterns that would match everything
                if pattern_spec._is_empty_pattern:
                    continue
                if (
                    pattern_spec.has_language_constraint
                    and ast.language not in pattern_spec.languages
                ):
                    continue

                if pattern_spec.source_mode:
                    if source is None:
                        try:
                            source = Path(ast.file_path).read_text(errors="replace")
                        except OSError:
                            source = ""
                    file_findings.extend(self._match_source_pattern(ast, pattern_spec, source))
                    cap = min(cap, self._MAX_REGEX_FINDINGS_PER_FILE)
                else:
                    file_findings.extend(self._match_pattern(ast, pattern_spec))
                if len(file_findings) >= cap:
                    break

            findings.extend(file_findings[:cap])

        return findings

    def _match_source_pattern(
        self, ast: FileAST, pattern: PatternSpec, source: str
    ) -> list[Finding]:
        """Evaluate normalized source, sequence, negative, and lexical-taint rules."""
        if not source:
            return []
        if pattern._file_re and not pattern._file_re.search(ast.file_path):
            return []

        findings: list[Finding] = []
        lines = source.splitlines()
        for base_line, segment in self._source_segments(ast, source, pattern.scope):
            matches = pattern.find_source_matches(segment)
            for start, matched_text in matches:
                line_num = base_line + segment.count("\n", 0, start)
                snippet = lines[max(0, line_num - 1 - 5) : min(len(lines), line_num + 5)]
                msg = self._safe_format(
                    self.spec.message,
                    callee=matched_text[:80],
                    line=line_num,
                    file=ast.file_path,
                    source=matched_text[:80],
                    source_line=line_num,
                    sink=matched_text[:80],
                    sink_line=line_num,
                    source_type="lexical",
                    sink_type=pattern.pattern_type,
                )
                findings.append(
                    self._create_finding(
                        file_path=ast.file_path,
                        line_start=line_num,
                        line_end=line_num,
                        code_snippet="\n".join(snippet),
                        message=msg,
                        evidence_state=EvidenceState.CANDIDATE,
                        disposition=pattern.disposition,
                    )
                )
                if len(findings) >= self._MAX_REGEX_FINDINGS_PER_FILE:
                    return findings
        return findings

    @staticmethod
    def _source_segments(ast: FileAST, source: str, scope: str) -> list[tuple[int, str]]:
        """Return 1-based line offsets and text for file/function scoped rules."""
        if scope != "function" or not ast.functions:
            return [(1, source)]
        source_lines = source.splitlines(keepends=True)
        segments: list[tuple[int, str]] = []
        seen: set[tuple[int, int]] = set()
        for function in ast.functions:
            bounds = (function.line_start, function.line_end)
            if bounds in seen:
                continue
            seen.add(bounds)
            start = max(function.line_start - 1, 0)
            end = max(function.line_end, function.line_start)
            segments.append((function.line_start, "".join(source_lines[start:end])))
        return segments or [(1, source)]

    def _match_pattern(self, ast: FileAST, pattern: PatternSpec) -> list[Finding]:
        """Match a single pattern against a file AST."""
        findings: list[Finding] = []
        # Pre-check: if pattern requires args but no calls have args, skip early
        needs_args = pattern._args_match_re is not None or pattern._args_exclude_re is not None
        needs_context = bool(
            pattern._call_context_required_res or pattern._call_context_excluded_res
        )
        source = ""
        if needs_context:
            try:
                source = Path(ast.file_path).read_text(errors="replace")
            except OSError:
                return []

        for call in ast.calls:
            # Early termination when file cap reached
            if len(findings) >= self._MAX_FINDINGS_PER_FILE:
                break

            # Early skip: if args pattern required but call has no arguments
            if needs_args and not call.arguments:
                continue

            callee_full = f"{call.receiver}.{call.callee}" if call.receiver else call.callee

            # Match function name (skip if match-all, use pre-compiled regex otherwise)
            if not pattern._callee_match_all and pattern._callee_re:
                matcher = (
                    pattern._callee_re.fullmatch
                    if pattern.callee_match_mode == "full"
                    else pattern._callee_re.search
                )
                if not matcher(callee_full) and not matcher(f"{callee_full}("):
                    continue

            args_text = " ".join(call.arguments)
            if pattern.args_match_index is not None:
                if pattern.args_match_index >= len(call.arguments):
                    continue
                args_text = call.arguments[pattern.args_match_index]

            # Match arguments (pre-compiled regex)
            if pattern._args_match_re:
                if not pattern._args_match_re.search(args_text):
                    continue

            if pattern._missing_args_res:
                if all(regex.search(args_text) for regex in pattern._missing_args_res):
                    continue

            # Negative match (pre-compiled regex)
            if pattern._args_exclude_re:
                if pattern._args_exclude_re.search(args_text):
                    continue

            # Match receiver (pre-compiled regex)
            if pattern._receiver_re:
                if not call.receiver or not pattern._receiver_re.search(call.receiver):
                    continue

            if needs_context:
                context = self._call_context_source(ast, source, call.line)
                if any(not regex.search(context) for regex in pattern._call_context_required_res):
                    continue
                if any(regex.search(context) for regex in pattern._call_context_excluded_res):
                    continue

            msg = self._safe_format(
                self.spec.message,
                callee=callee_full,
                line=call.line,
                file=ast.file_path,
                source=(" ".join(call.arguments)[:80] or callee_full),
                source_line=call.line,
                sink=callee_full,
                sink_line=call.line,
                source_type="call_argument",
                sink_type="call",
            )

            findings.append(
                self._create_finding(
                    file_path=ast.file_path,
                    line_start=call.line,
                    line_end=call.line,
                    code_snippet="",
                    message=msg,
                    evidence_state=EvidenceState.CANDIDATE,
                    disposition=pattern.disposition,
                )
            )

        return findings

    @staticmethod
    def _call_context_source(ast: FileAST, source: str, line: int) -> str:
        """Return the smallest parsed function containing a call, or the file."""
        candidates = [
            function
            for function in ast.functions
            if function.line_start <= line <= function.line_end
        ]
        if not candidates:
            return source
        function = min(candidates, key=lambda item: item.line_end - item.line_start)
        lines = source.splitlines(keepends=True)
        start = max(function.line_start - 1, 0)
        end = max(function.line_end, function.line_start)
        return "".join(lines[start:end])


# --- YAML Spec Data Classes ---


class PatternSpec:
    """Normalized executable pattern from the compatibility YAML rule DSL."""

    _SOURCE_PRIMARY_FIELDS = (
        "regex_match",
        "annotation_match",
        "attribute_match",
        "class_match",
        "decorator_match",
        "import_match",
        "config_match",
        "content_match",
        "assignment_match",
    )
    _SOURCE_REQUIRED_FIELDS = (
        "must_contain",
        "context",
        "context_match",
        "context_check",
        "class_context",
        "method_match",
        "value_match",
        "param_type_match",
        "taint_source",
    )
    _SOURCE_EXCLUDED_FIELDS = (
        "negative_match",
        "exclude_match",
        "exclude_context",
        "missing_match",
        "missing_pattern",
        "missing_context",
        "missing_annotation",
        "missing_filter",
        "missing_attribute",
        "missing_sibling",
        "missing_header",
        "missing_validation",
        "block_missing",
    )
    _CALL_CONTEXT_REQUIRED_FIELDS = (
        "context",
        "context_match",
        "context_check",
        "class_context",
        "method_match",
        "value_match",
        "param_type_match",
        "taint_source",
    )
    _CALL_CONTEXT_EXCLUDED_FIELDS = (
        "exclude_context",
        "missing_match",
        "missing_pattern",
        "missing_context",
        "missing_annotation",
        "missing_filter",
        "missing_attribute",
        "missing_sibling",
        "missing_header",
        "missing_validation",
        "missing_check",
        "missing_transform",
        "missing_guard",
        "block_missing",
    )
    _SOURCE_ONLY_FIELDS = frozenset(
        _SOURCE_PRIMARY_FIELDS
        + _SOURCE_REQUIRED_FIELDS
        + _SOURCE_EXCLUDED_FIELDS
        + (
            "argument_check",
            "block_match",
            "decorator_absent",
            "entropy_threshold",
            "file_match",
            "multi_match",
            "sequence_match",
            "steps",
            "taint",
            "version_match",
        )
    )

    def __init__(self, data: dict[str, Any]) -> None:
        self.raw = dict(data)
        legacy_pattern = data.get("pattern")
        force_call_mode = False
        if (
            legacy_pattern
            and "pattern_type" not in data
            and "callee" not in data
            and "callee_match" not in data
        ):
            # A pattern paired with argument constraints describes one parsed
            # call. File-wide matching can otherwise combine a callee and an
            # argument expression from unrelated statements or functions.
            if any(
                field in data
                for field in (
                    "args_match",
                    "args_exclude",
                    "missing_args",
                    *self._CALL_CONTEXT_REQUIRED_FIELDS,
                    *self._CALL_CONTEXT_EXCLUDED_FIELDS,
                )
            ):
                force_call_mode = True
                data = {**data, "pattern_type": "call", "callee": legacy_pattern}
            else:
                data = {**data, "pattern_type": "regex", "match": legacy_pattern}
        if "callee_chain" in data and not (data.get("callee") or data.get("callee_match")):
            chain = data["callee_chain"]
            if isinstance(chain, list) and len(chain) >= 2:
                data = {**data, "receiver": chain[0], "callee": chain[1]}
        if "receiver_match" in data and "receiver" not in data:
            data = {**data, "receiver": data["receiver_match"]}

        self.pattern_type = str(data.get("pattern_type") or "call")
        self.callee_match_mode = str(data.get("callee_match_mode") or "search")
        raw_disposition = str(data.get("disposition") or FindingDisposition.ADVISORY.value)
        try:
            self.disposition = FindingDisposition(raw_disposition)
        except ValueError:
            logger.warning(
                "Unsupported pattern disposition %r; using advisory",
                raw_disposition,
            )
            self.disposition = FindingDisposition.ADVISORY
        relational_source_pattern = bool(
            data.get("multi_match")
            or data.get("sequence_match")
            or data.get("steps")
            or isinstance(data.get("taint"), dict)
            or self.pattern_type in {"negative_check", "sequence", "taint"}
        )
        self.scope = str(data.get("scope") or ("function" if relational_source_pattern else "file"))
        self.max_lines_between = int(data.get("max_lines_between") or 50)
        self.entropy_threshold = float(data.get("entropy_threshold") or 0.0)
        self.callee: str | None = data.get("callee") or data.get("callee_match")
        self.receiver: str | None = data.get("receiver")
        self.args_match: str | None = data.get("args_match")
        self.args_exclude: str | None = data.get("args_exclude")
        raw_args_match_index = data.get("args_match_index")
        self.args_match_index: int | None = None
        if raw_args_match_index is not None:
            try:
                parsed_index = int(raw_args_match_index)
            except TypeError, ValueError:
                logger.warning(
                    "Unsupported args_match_index %r; matching all arguments",
                    raw_args_match_index,
                )
            else:
                if parsed_index < 0:
                    logger.warning(
                        "Unsupported args_match_index %r; matching all arguments",
                        raw_args_match_index,
                    )
                else:
                    self.args_match_index = parsed_index
        declared_languages = self._string_values(data.get("languages"))
        self.has_language_constraint = bool(declared_languages)
        self.languages = [LANG_MAP[name] for name in declared_languages if name in LANG_MAP]

        explicit_source_type = self.pattern_type in {
            "regex",
            "negative_check",
            "sequence",
            "taint",
            "entropy",
        }
        has_structural_source_fields = any(
            field in data
            for field in (
                *self._SOURCE_PRIMARY_FIELDS,
                "argument_check",
                "block_match",
                "decorator_absent",
                "entropy_threshold",
                "file_match",
                "multi_match",
                "sequence_match",
                "steps",
                "taint",
                "version_match",
            )
        )
        has_source_fields = has_structural_source_fields or (
            not self.callee and any(field in data for field in self._SOURCE_ONLY_FIELDS)
        )
        callee_is_source_regex = bool(self.callee and "\\(" in self.callee and not force_call_mode)
        self.source_mode = explicit_source_type or has_source_fields or callee_is_source_regex

        regex_flags = re.IGNORECASE | re.MULTILINE
        flag_value = str(data.get("flags") or "")
        if data.get("multiline") or "s" in flag_value:
            regex_flags |= re.DOTALL
        self._regex_flags = regex_flags

        self._file_re = self._compile(data.get("file_match"))
        self._primary_res: list[re.Pattern[str]] = []
        self._required_res: list[re.Pattern[str]] = []
        self._excluded_res: list[re.Pattern[str]] = []
        self._sequence_res: list[re.Pattern[str]] = []
        self._block: tuple[re.Pattern[str], re.Pattern[str], re.Pattern[str]] | None = None
        self._decorator_absent: tuple[re.Pattern[str], re.Pattern[str]] | None = None
        self._argument_limit: int | None = None

        if self.source_mode:
            self._configure_source(data)

        self._call_context_required_res = (
            self._compile_many(
                [
                    value
                    for field in self._CALL_CONTEXT_REQUIRED_FIELDS
                    for value in self._string_values(data.get(field))
                ]
            )
            if not self.source_mode
            else []
        )
        self._call_context_excluded_res = (
            self._compile_many(
                [
                    value
                    for field in self._CALL_CONTEXT_EXCLUDED_FIELDS
                    for value in self._string_values(data.get(field))
                ]
            )
            if not self.source_mode
            else []
        )

        self._callee_match_all = self.callee in (".*", ".+", "^.*$", None)
        self._callee_re = (
            self._compile(self.callee)
            if self.callee and not self._callee_match_all and not self.source_mode
            else None
        )
        self._receiver_re = self._compile(self.receiver) if self.receiver else None
        self._args_match_re = self._compile(self.args_match) if self.args_match else None
        self._args_exclude_re = self._compile(self.args_exclude) if self.args_exclude else None
        self._missing_args_res = [
            regex
            for value in self._string_values(data.get("missing_args"))
            if (regex := self._compile(value)) is not None
        ]

        self._is_empty_pattern = not self.is_executable
        if self.callee_match_mode not in {"search", "full"}:
            logger.warning(
                "Unsupported callee_match_mode %r; using search",
                self.callee_match_mode,
            )
            self.callee_match_mode = "search"

    @property
    def is_executable(self) -> bool:
        if self.source_mode:
            return bool(
                self._primary_res
                or self._sequence_res
                or self._block
                or self._decorator_absent
                or (self._file_re and self._excluded_res)
            )
        return bool(
            (self.callee and not self._callee_match_all)
            or self.receiver
            or self.args_match
            or self.args_exclude
            or self._missing_args_res
        )

    def _configure_source(self, data: dict[str, Any]) -> None:
        primary_values: list[str] = []
        if self.pattern_type in {"regex", "negative_check", "entropy"}:
            primary_values.extend(self._string_values(data.get("match") or data.get("pattern")))
        if self.callee:
            primary_values.append(self.callee)
        if self.receiver:
            primary_values.append(self.receiver)
        for field in self._SOURCE_PRIMARY_FIELDS:
            primary_values.extend(self._string_values(data.get(field)))

        required_values: list[str] = []
        for field in self._SOURCE_REQUIRED_FIELDS:
            if field == "must_contain" and self.pattern_type == "negative_check":
                continue
            required_values.extend(self._string_values(data.get(field)))
        version = data.get("version_match")
        if version:
            required_values.extend(
                re.sub(r"(^|\|)[<>~=^]+", r"\1", value) for value in self._string_values(version)
            )
        if self.args_match:
            required_values.append(self.args_match)

        excluded_values: list[str] = []
        for field in self._SOURCE_EXCLUDED_FIELDS:
            excluded_values.extend(self._string_values(data.get(field)))
        excluded_values.extend(self._string_values(self.args_exclude))
        excluded_values.extend(self._string_values(data.get("missing_args")))
        excluded_values.extend(self._string_values(data.get("sanitizers")))
        if self.pattern_type == "negative_check":
            excluded_values.extend(self._string_values(data.get("must_contain")))

        multi = self._string_values(data.get("multi_match"))
        if multi:
            if not primary_values:
                primary_values.append(multi[0])
                multi = multi[1:]
            required_values.extend(multi)

        sequence = self._string_values(data.get("sequence_match"))
        if data.get("steps"):
            sequence.extend(
                value
                for step in data["steps"]
                if isinstance(step, dict)
                for value in self._string_values(step.get("match"))
            )

        raw_taint = data.get("taint")
        taint: dict[str, Any] = raw_taint if isinstance(raw_taint, dict) else data
        if self.pattern_type == "taint" or isinstance(raw_taint, dict):
            source_values = self._string_values(taint.get("source"))
            sink_values = self._string_values(taint.get("sink"))
            sequence = [*source_values, *sink_values]
            excluded_values.extend(self._string_values(taint.get("missing_sanitizer")))
            excluded_values.extend(self._string_values(taint.get("sanitizers")))

        block = data.get("block_match")
        if isinstance(block, dict):
            start = self._compile(block.get("start"))
            end = self._compile(block.get("end"))
            missing = self._compile(block.get("missing"))
            if start and end and missing:
                self._block = (start, end, missing)

        absent = data.get("decorator_absent")
        if isinstance(absent, dict):
            function = self._compile(absent.get("function_pattern"))
            decorator = self._compile(absent.get("expected_decorator"))
            if function and decorator:
                self._decorator_absent = (function, decorator)

        argument_check = data.get("argument_check")
        if isinstance(argument_check, dict) and "iterations_below" in argument_check:
            self._argument_limit = int(argument_check["iterations_below"])

        self._primary_res = self._compile_many(primary_values)
        self._required_res = self._compile_many(required_values)
        self._excluded_res = self._compile_many(excluded_values)
        self._sequence_res = self._compile_many(sequence)

    def find_source_matches(self, source: str) -> list[tuple[int, str]]:
        """Return source offsets and evidence text for this pattern."""
        if self._block:
            start_re, end_re, missing_re = self._block
            start = start_re.search(source)
            if not start:
                return []
            end = end_re.search(source, start.end())
            block = source[start.start() : end.end() if end else len(source)]
            if missing_re.search(block):
                return []
            return [(start.start(), start.group(0))]

        if self._decorator_absent:
            function_re, decorator_re = self._decorator_absent
            matches: list[tuple[int, str]] = []
            for match in function_re.finditer(source):
                prefix_start = max(0, source.rfind("\n", 0, match.start() - 1) - 500)
                prefix = source[prefix_start : match.start()]
                if not decorator_re.search(prefix):
                    matches.append((match.start(), match.group(0)))
            return matches[:2]

        if self._sequence_res:
            position = 0
            first: re.Match[str] | None = None
            previous_line = 1
            for regex in self._sequence_res:
                sequence_match = regex.search(source, position)
                if not sequence_match:
                    return []
                line = source.count("\n", 0, sequence_match.start()) + 1
                if first is not None and line - previous_line > self.max_lines_between:
                    return []
                first = first or sequence_match
                previous_line = line
                position = sequence_match.end()
            assert first is not None
            if any(regex.search(source) for regex in self._excluded_res):
                return []
            return [(first.start(), first.group(0))]

        if any(not regex.search(source) for regex in self._required_res):
            return []
        if any(regex.search(source) for regex in self._excluded_res):
            return []

        if self._primary_res:
            candidates = list(self._primary_res[0].finditer(source))
            for required_primary in self._primary_res[1:]:
                if not required_primary.search(source):
                    return []
        elif self._file_re:
            return [(0, "file")]
        else:
            return []

        results: list[tuple[int, str]] = []
        for match in candidates:
            evidence = match.group(0)
            if self._argument_limit is not None:
                line_end = source.find("\n", match.start())
                line_text = source[match.start() : line_end if line_end >= 0 else len(source)]
                numbers = [int(value) for value in re.findall(r"\b\d[\d_]*\b", line_text)]
                if not numbers or min(numbers) >= self._argument_limit:
                    continue
            if self.entropy_threshold and self._entropy(evidence) < self.entropy_threshold:
                continue
            results.append((match.start(), evidence))
            if len(results) >= 2:
                break
        return results

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = {char: value.count(char) for char in set(value)}
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def _string_values(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value if isinstance(item, (str, int, float))]
        return []

    def _compile(self, value: Any) -> re.Pattern[str] | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            return re.compile(value, self._regex_flags)
        except re.error as error:
            logger.warning("Invalid rule regex %r: %s", value, error)
            return None

    def _compile_many(self, values: list[str]) -> list[re.Pattern[str]]:
        return [regex for value in values if (regex := self._compile(value)) is not None]


class TaintSpec:
    """Specification for taint-based matching."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.sink_types: list[str] = data.get("sink_types", [])
        self.source_types: list[str] = data.get("source_types", [])
        self.sink_pattern: str | None = data.get("sink_pattern")
        self.source_pattern: str | None = data.get("source_pattern")
        self.ignore_sanitizers: bool = data.get("ignore_sanitizers", False)
        # Pre-compile regex patterns for performance
        self._sink_pattern_re: re.Pattern[str] | None = (
            re.compile(self.sink_pattern, re.IGNORECASE) if self.sink_pattern else None
        )
        self._source_pattern_re: re.Pattern[str] | None = (
            re.compile(self.source_pattern, re.IGNORECASE) if self.source_pattern else None
        )
        # Pre-build sets for O(1) lookup
        self._sink_types_set: set[str] = set(self.sink_types)
        self._source_types_set: set[str] = set(self.source_types)


class SemanticSpec:
    """Normalized structured evidence detector configuration."""

    _SUPPORTED_KINDS = {"database_race"}

    def __init__(self, data: dict[str, Any]) -> None:
        self.kind = str(data.get("kind") or "")
        self.same_receiver = bool(data.get("same_receiver", True))
        self.max_lines_between = int(data.get("max_lines_between") or 20)
        self.read_callee = str(data.get("read_callee") or "")
        self.write_callee = str(data.get("write_callee") or "")
        self.receiver_match = str(data.get("receiver_match") or "")
        self.required_between = str(data.get("required_between") or "")
        self.defense_match = str(data.get("defense_match") or "")
        self._read_callee_re = re.compile(self.read_callee, re.IGNORECASE)
        self._write_callee_re = re.compile(self.write_callee, re.IGNORECASE)
        self._receiver_re = re.compile(self.receiver_match, re.IGNORECASE)
        self._required_between_re = re.compile(self.required_between, re.IGNORECASE)
        self._defense_re = re.compile(self.defense_match, re.IGNORECASE)

    @property
    def is_executable(self) -> bool:
        return bool(
            self.kind in self._SUPPORTED_KINDS
            and self.read_callee
            and self.write_callee
            and self.receiver_match
            and self.required_between
            and self.defense_match
            and self.max_lines_between > 0
        )


class YAMLRuleSpec:
    """Full specification parsed from a YAML rule definition."""

    def __init__(self, data: dict[str, Any]) -> None:
        default_msg = "Security finding detected at {sink} (line {sink_line})"
        self.message: str = data.get("message", default_msg)
        self.taint: TaintSpec | None = None
        self.semantic: SemanticSpec | None = None
        self.patterns: list[PatternSpec] = []

        if "taint" in data:
            self.taint = TaintSpec(data["taint"])
        if isinstance(data.get("semantic"), dict):
            semantic = SemanticSpec(data["semantic"])
            if semantic.is_executable:
                self.semantic = semantic
            else:
                logger.warning("Rule %s has a non-executable semantic detector", data.get("id"))

        rule_id = data.get("id", "<unknown>")
        for p in data.get("patterns", []):
            spec = PatternSpec(p)
            if spec._is_empty_pattern:
                logger.warning(
                    "Rule %s has a match-all pattern with no filters (callee=%r) - "
                    "skipping to prevent false positive explosion",
                    rule_id,
                    spec.callee,
                )
            self.patterns.append(spec)


# --- Loader ---


def load_yaml_rules(path: Path) -> list[YAMLRule]:
    """Load rules from a YAML file or directory of YAML files."""
    rules: list[YAMLRule] = []

    if path.is_file():
        rules.extend(_load_rules_from_file(path))
    elif path.is_dir():
        for f in sorted(path.glob("**/*.yml")):
            rules.extend(_load_rules_from_file(f))
        for f in sorted(path.glob("**/*.yaml")):
            rules.extend(_load_rules_from_file(f))

    logger.info("Loaded %d YAML rules from %s", len(rules), path)
    return rules


def _load_rules_from_file(path: Path) -> list[YAMLRule]:
    """Load rules from a single YAML file."""
    rules: list[YAMLRule] = []

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logger.error("Failed to load YAML rules from %s: %s", path, e)
        return rules

    if not data:
        return rules

    # Support single rule or list of rules
    rule_list: list[dict[str, Any]] = []
    if isinstance(data, list):
        rule_list = data
    elif isinstance(data, dict):
        if "rules" in data:
            rule_list = data["rules"]
        else:
            rule_list = [data]

    for rule_data in rule_list:
        try:
            rule = _parse_rule(rule_data)
            if rule is not None:
                rules.append(rule)
        except Exception as e:
            logger.error("Failed to parse YAML rule in %s: %s", path, e)

    return rules


def _parse_rule(data: dict[str, Any]) -> YAMLRule | None:
    """Parse a single rule definition from YAML data.

    Returns None if the rule specifies languages that are all unsupported
    (e.g. csharp, ruby, php) — those rules cannot match any scanned file.
    """
    rule_id = data["id"]
    if data.get("enabled") is False:
        logger.info("Skipping disabled reference-only rule %s", rule_id)
        return None
    raw_languages = data.get("languages", [])
    languages = [LANG_MAP[lang] for lang in raw_languages if lang in LANG_MAP]

    # If YAML specified languages but NONE resolved, this rule can never match
    if raw_languages and not languages:
        logger.info(
            "Skipping rule %s: all specified languages %s are unsupported",
            rule_id,
            raw_languages,
        )
        return None

    severity = SEVERITY_MAP.get(data.get("severity", "medium"), Severity.MEDIUM)

    definition = RuleDefinition(
        id=rule_id,
        name=data.get("name", rule_id),
        description=data.get("description", ""),
        severity=severity,
        default_confidence=data.get("confidence", 0.7),
        languages=languages,
        cwe_id=data.get("cwe_id"),
        owasp_category=data.get("owasp_category"),
        masvs_category=data.get("masvs_category"),
        requires_taint_path=bool(data.get("taint")),
        llm_verify_threshold=data.get("llm_verify_threshold", 0.7),
        defense_patterns=data.get("defense_patterns", []),
    )

    spec = YAMLRuleSpec(data)
    # Serialize back to YAML for dashboard display
    import yaml as _yaml

    raw_yaml = _yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)
    return YAMLRule(definition=definition, spec=spec, raw_yaml=raw_yaml)


def load_and_register_yaml_rules(path: Path) -> int:
    """Load YAML rules and register them in the global registry."""
    rules = load_yaml_rules(path)
    for rule in rules:
        register_rule(rule)
    return len(rules)
