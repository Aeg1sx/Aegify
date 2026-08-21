"""Bounded flow-, field-, and allocation-site-sensitive global taint analysis.

The solver deliberately operates on the normalized source program graph instead
of pairing sources and sinks by file.  It propagates distinct origins through
locals, allocation-site fields, call arguments, receivers, and return values.
It remains a bounded source analysis: compiler-produced SCIP edges improve call
resolution, while unresolved calls use an explicitly conservative taint-through
summary.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codeguard.modelpacks import JvmLibraryModel, JvmModelPack, load_jvm_model_pack
from codeguard.models import (
    CallSite,
    FileAST,
    FunctionDef,
    TaintAnalysisSummary,
    TaintFlow,
    TaintPropagation,
    TaintSink,
    TaintSource,
)

_TraceMap = dict[str, "_Trace"]
_CallString = tuple[str, ...]


@dataclass(frozen=True)
class _Trace:
    source: TaintSource
    path: tuple[TaintPropagation, ...]
    sanitized: bool = False
    sanitizer: str | None = None
    sanitized_for: frozenset[str] = frozenset()


@dataclass(frozen=True)
class _Statement:
    node_id: str
    line_start: int
    line_end: int
    code: str
    syntax_kind: str


@dataclass
class _FunctionContext:
    node_id: str
    definition: FunctionDef
    ast: FileAST
    statements: list[_Statement] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)


@dataclass(frozen=True)
class _SinkEvent:
    sink: TaintSink
    call: CallSite


class StructuredTaintAnalyzer:
    """Compute bounded global taint summaries to a deterministic fixed point."""

    _ACCESS = re.compile(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\b")
    _ASSIGNMENT = re.compile(r"(?<![=!<>])=(?!=)")
    _NEW_JAVA = re.compile(r"\bnew\s+([A-Z][\w.$]*)\s*\(")
    _NEW_KOTLIN = re.compile(r"^\s*([A-Z][\w.$]*)\s*\(")
    _RETURN = re.compile(r"\breturn\b(?P<value>.*)", re.DOTALL)
    _ROUTE_MARKERS = (
        "Mapping",
        "@app.route",
        "@app.get",
        "@app.post",
        "@router.get",
        "@router.post",
        "@api_view",
    )
    _KEYWORDS = {
        "as",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "do",
        "else",
        "false",
        "final",
        "for",
        "fun",
        "function",
        "if",
        "in",
        "interface",
        "let",
        "new",
        "null",
        "return",
        "static",
        "throw",
        "true",
        "try",
        "val",
        "var",
        "void",
        "when",
        "while",
    }
    _CONTROL_STATEMENTS = {
        "do_statement",
        "for_in_statement",
        "for_statement",
        "if_expression",
        "if_statement",
        "switch_expression",
        "switch_statement",
        "try_expression",
        "try_statement",
        "try_with_resources_statement",
        "when_expression",
        "while_expression",
        "while_statement",
    }

    def __init__(
        self,
        config: Any,
        *,
        max_iterations: int = 64,
        context_depth: int = 2,
        max_contexts: int = 10_000,
        jvm_model_pack: JvmModelPack | None = None,
    ) -> None:
        if context_depth < 1 or context_depth > 4:
            raise ValueError("context_depth must be between 1 and 4")
        if max_contexts < 1:
            raise ValueError("max_contexts must be positive")
        self.config = config
        self.max_iterations = max_iterations
        self.context_depth = context_depth
        self.max_contexts = max_contexts
        self.jvm_model_pack = jvm_model_pack or load_jvm_model_pack()
        self.summary = TaintAnalysisSummary(
            enabled=True,
            context_depth=context_depth,
            library_model_pack=self.jvm_model_pack.pack_version,
            library_models_loaded=len(self.jvm_model_pack.models),
        )
        self._program_graph: Any = None
        self._call_graph: Any = None
        self._contexts: dict[str, _FunctionContext] = {}
        self._functions_by_name: dict[str, list[str]] = defaultdict(list)
        self._context_for_call: dict[int, str] = {}
        self._edge_targets: dict[tuple[str, str, int, int], set[str]] = defaultdict(set)
        self._source_traces: dict[tuple[str, int], _TraceMap] = defaultdict(dict)
        self._sink_events: list[_SinkEvent] = []
        self._heap_objects: set[str] = set()
        self._argument_events: set[tuple[str, str, str, int]] = set()
        self._return_events: set[tuple[str, str, int]] = set()
        self._object_return_events: set[tuple[str, str, int]] = set()
        self._field_reads: set[tuple[str, int, str]] = set()
        self._field_writes: set[tuple[str, int, str]] = set()
        self._strong_update_events: set[tuple[str, int, str]] = set()
        self._source_ids: set[str] = set()
        self._sink_ids: set[tuple[str, int, int, str]] = set()
        self._library_applications: set[tuple[str, str, _CallString, int, int]] = set()

    def analyze(
        self,
        file_asts: list[FileAST],
        call_graph: Any,
        program_graph: Any,
    ) -> tuple[list[TaintFlow], TaintAnalysisSummary]:
        self._program_graph = program_graph
        self._call_graph = call_graph
        self._build_contexts(file_asts)
        self._index_call_targets()

        parameter_taints: dict[tuple[str, _CallString, str], _TraceMap] = defaultdict(dict)
        parameter_points: dict[tuple[str, _CallString, str], set[str]] = defaultdict(set)
        return_taints: dict[tuple[str, _CallString], _TraceMap] = defaultdict(dict)
        return_points: dict[tuple[str, _CallString], set[str]] = defaultdict(set)
        heap_taints: dict[str, _TraceMap] = defaultdict(dict)
        heap_points: dict[str, set[str]] = defaultdict(set)
        self._seed_sources_and_sinks(parameter_taints)
        active_contexts: set[tuple[str, _CallString]] = {
            (function_id, ()) for function_id in self._contexts
        }

        flows: dict[tuple[str, str, int, str, _CallString], TaintFlow] = {}
        limit = min(
            self.max_iterations,
            max(8, len(self._contexts) * 4 + 8),
        )
        for iteration in range(1, limit + 1):
            before = self._state_signature(
                parameter_taints,
                parameter_points,
                return_taints,
                return_points,
                heap_taints,
                heap_points,
                active_contexts,
            )
            current_flows: dict[tuple[str, str, int, str, _CallString], TaintFlow] = {}
            for function_id, call_string in sorted(active_contexts):
                context = self._contexts[function_id]
                self._evaluate_function(
                    context,
                    call_string,
                    parameter_taints,
                    parameter_points,
                    return_taints,
                    return_points,
                    heap_taints,
                    heap_points,
                    current_flows,
                    active_contexts,
                )
            flows = current_flows
            self.summary.iterations = iteration
            after = self._state_signature(
                parameter_taints,
                parameter_points,
                return_taints,
                return_points,
                heap_taints,
                heap_points,
                active_contexts,
            )
            if after == before:
                break
        else:
            self.summary.truncated = True
            self.summary.warnings.append(
                f"global taint fixed point hit the {limit}-iteration bound"
            )

        self.summary.flows = len(flows)
        self.summary.argument_propagations = len(self._argument_events)
        self.summary.return_propagations = len(self._return_events)
        self.summary.object_return_propagations = len(self._object_return_events)
        self.summary.field_reads = len(self._field_reads)
        self.summary.field_writes = len(self._field_writes)
        self.summary.heap_strong_updates = len(self._strong_update_events)
        self.summary.heap_objects = len(self._heap_objects)
        self.summary.contexts_analyzed = len(active_contexts)
        self.summary.sources = len(self._source_ids)
        self.summary.sinks = len(self._sink_ids)
        self.summary.library_summary_applications = len(self._library_applications)
        return list(flows.values()), self.summary

    def _build_contexts(self, file_asts: list[FileAST]) -> None:
        self._contexts = {}
        self._functions_by_name = defaultdict(list)
        self._context_for_call = {}
        for ast in file_asts:
            seen: set[str] = set()
            for definition in ast.functions:
                node_id = definition.symbol_id or definition.qualified_name
                if node_id in seen:
                    continue
                seen.add(node_id)
                statements = self._statements_for(node_id, definition)
                calls = [
                    call
                    for call in ast.calls
                    if definition.line_start <= call.line <= definition.line_end
                    and (
                        call.caller_symbol_id == node_id
                        or call.in_function == definition.name
                        or call.in_function == definition.qualified_name
                        or definition.qualified_name.endswith(f".{call.in_function or ''}")
                    )
                ]
                context = _FunctionContext(
                    node_id=node_id,
                    definition=definition,
                    ast=ast,
                    statements=statements,
                    calls=sorted(calls, key=lambda call: (call.line, call.column)),
                )
                self._contexts[node_id] = context
                for key in {definition.name, definition.qualified_name}:
                    if node_id not in self._functions_by_name[key]:
                        self._functions_by_name[key].append(node_id)
                for call in calls:
                    self._context_for_call[id(call)] = node_id

    def _statements_for(self, node_id: str, definition: FunctionDef) -> list[_Statement]:
        statements: list[_Statement] = []
        if self._program_graph is not None:
            for graph_node, attributes in self._program_graph.nodes(data=True):
                if (
                    attributes.get("kind") != "statement"
                    or attributes.get("function") != node_id
                    or attributes.get("syntax_kind") in self._CONTROL_STATEMENTS
                ):
                    continue
                statements.append(
                    _Statement(
                        node_id=str(graph_node),
                        line_start=int(attributes.get("line_start", 0)),
                        line_end=int(attributes.get("line_end", 0)),
                        code=str(attributes.get("code", "")),
                        syntax_kind=str(attributes.get("syntax_kind", "")),
                    )
                )
        if statements:
            return sorted(
                statements,
                key=lambda item: (item.line_start, item.line_end, item.node_id),
            )
        try:
            lines = Path(definition.file_path).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return []
        for line_number in range(definition.line_start, definition.line_end + 1):
            if line_number > len(lines):
                break
            code = lines[line_number - 1].strip()
            if code:
                statements.append(
                    _Statement(
                        node_id=f"{node_id}::line:{line_number}",
                        line_start=line_number,
                        line_end=line_number,
                        code=code,
                        syntax_kind="source-line",
                    )
                )
        return statements

    def _index_call_targets(self) -> None:
        self._edge_targets = defaultdict(set)
        if self._call_graph is None:
            return
        for source, target, attributes in self._call_graph.edges(data=True):
            call = attributes.get("call_site")
            if call is not None:
                self._edge_targets[
                    (str(source), str(call.file_path), int(call.line), int(call.column))
                ].add(str(target))
                continue
            line = int(attributes.get("line", 0) or 0)
            file_path = str(attributes.get("file_path", ""))
            if line and file_path:
                self._edge_targets[(str(source), file_path, line, -1)].add(str(target))

    def _seed_sources_and_sinks(
        self,
        parameter_taints: dict[tuple[str, _CallString, str], _TraceMap],
    ) -> None:
        for context in self._contexts.values():
            is_entry = self._is_entry_point(context)
            if is_entry:
                for parameter in context.definition.parameters:
                    if parameter in {"self", "this"}:
                        continue
                    source = TaintSource(
                        variable=parameter,
                        file_path=context.definition.file_path,
                        line=context.definition.line_start,
                        source_type="http_param",
                        in_function=context.definition.qualified_name,
                    )
                    trace = self._source_trace(source)
                    origin = self._origin_id(source)
                    self._source_ids.add(origin)
                    self._merge_traces(
                        parameter_taints[(context.node_id, (), parameter)],
                        {origin: trace},
                    )

            source_patterns = self.config.sources.get(context.ast.language, [])
            sink_patterns = self.config.sinks.get(context.ast.language, [])
            for statement in context.statements:
                for pattern in source_patterns:
                    if not self._pattern_matches(pattern.pattern, statement.code):
                        continue
                    source = TaintSource(
                        variable=pattern.pattern.removesuffix("("),
                        file_path=context.definition.file_path,
                        line=statement.line_start,
                        source_type=pattern.source_type,
                        in_function=context.definition.qualified_name,
                    )
                    trace = self._source_trace(source)
                    origin = self._origin_id(source)
                    self._source_ids.add(origin)
                    self._merge_traces(
                        self._source_traces[(context.definition.file_path, statement.line_start)],
                        {origin: trace},
                    )
            for call in context.calls:
                call_text = self._call_text(call)
                for pattern in source_patterns:
                    if self._call_matches_pattern(pattern.pattern, call):
                        if self._line_has_source_type(
                            call.file_path, call.line, pattern.source_type
                        ):
                            break
                        source = TaintSource(
                            variable=call_text,
                            file_path=call.file_path,
                            line=call.line,
                            source_type=pattern.source_type,
                            in_function=context.definition.qualified_name,
                        )
                        trace = self._source_trace(source)
                        origin = self._origin_id(source)
                        self._source_ids.add(origin)
                        self._merge_traces(
                            self._source_traces[(call.file_path, call.line)],
                            {origin: trace},
                        )
                        break
                for argument in call.arguments:
                    for pattern in source_patterns:
                        if self._pattern_matches(pattern.pattern, argument):
                            if self._line_has_source_type(
                                call.file_path, call.line, pattern.source_type
                            ):
                                break
                            source = TaintSource(
                                variable=argument,
                                file_path=call.file_path,
                                line=call.line,
                                source_type=pattern.source_type,
                                in_function=context.definition.qualified_name,
                            )
                            trace = self._source_trace(source)
                            origin = self._origin_id(source)
                            self._source_ids.add(origin)
                            self._merge_traces(
                                self._source_traces[(call.file_path, call.line)],
                                {origin: trace},
                            )
                            break
                for pattern in sink_patterns:
                    if not self._call_matches_pattern(pattern.pattern, call):
                        continue
                    key = (call.file_path, call.line, call.column, pattern.sink_type)
                    if key not in self._sink_ids:
                        self._sink_ids.add(key)
                        self._sink_events.append(
                            _SinkEvent(
                                sink=TaintSink(
                                    function=call_text,
                                    file_path=call.file_path,
                                    line=call.line,
                                    sink_type=pattern.sink_type,
                                    argument_index=pattern.argument_index,
                                    in_function=context.definition.qualified_name,
                                ),
                                call=call,
                            )
                        )
                    break
        self.summary.sources = len(self._source_ids)
        self.summary.sinks = len(self._sink_ids)

    def _evaluate_function(
        self,
        context: _FunctionContext,
        call_string: _CallString,
        parameter_taints: dict[tuple[str, _CallString, str], _TraceMap],
        parameter_points: dict[tuple[str, _CallString, str], set[str]],
        return_taints: dict[tuple[str, _CallString], _TraceMap],
        return_points: dict[tuple[str, _CallString], set[str]],
        heap_taints: dict[str, _TraceMap],
        heap_points: dict[str, set[str]],
        flows: dict[tuple[str, str, int, str, _CallString], TaintFlow],
        active_contexts: set[tuple[str, _CallString]],
    ) -> None:
        locals_taint: dict[str, _TraceMap] = defaultdict(dict)
        local_points: dict[str, set[str]] = defaultdict(set)
        object_return_sites: dict[str, tuple[str, int]] = {}
        for parameter in context.definition.parameters:
            self._merge_traces(
                locals_taint[parameter],
                parameter_taints.get((context.node_id, call_string, parameter), {}),
            )
            local_points[parameter].update(
                parameter_points.get((context.node_id, call_string, parameter), set())
            )
        if context.definition.is_method:
            default_object = (
                f"type:{context.ast.repository_id}:{context.ast.module_path}:"
                f"{context.definition.class_name or '<anonymous>'}"
            )
            local_points["this"].update(
                parameter_points.get((context.node_id, call_string, "this"), {default_object})
            )
            local_points["self"].update(local_points["this"])
            self._heap_objects.update(local_points["this"])

        calls_by_statement: dict[str, list[CallSite]] = defaultdict(list)
        for call in context.calls:
            statement = self._statement_for_call(context.statements, call)
            if statement is not None:
                calls_by_statement[statement.node_id].append(call)

        sink_by_call = {
            (event.call.file_path, event.call.line, event.call.column): event
            for event in self._sink_events
            if event.call.file_path == context.definition.file_path
            and context.definition.line_start <= event.call.line <= context.definition.line_end
        }

        for statement in context.statements:
            assignment = self._assignment(statement.code)
            lhs = assignment[0] if assignment else None
            rhs = assignment[1] if assignment else statement.code
            calls = calls_by_statement.get(statement.node_id, [])
            call_returns: _TraceMap = {}
            call_return_points: set[str] = set()
            internal_call_on_rhs = False

            for call in calls:
                targets = self._resolve_call_targets(context, call)
                argument_states = [
                    self._expression_traces(
                        argument,
                        context,
                        statement,
                        locals_taint,
                        local_points,
                        heap_taints,
                        heap_points,
                        call_string,
                        object_return_sites,
                        include_line_sources=True,
                    )
                    for argument in call.arguments
                ]
                argument_points = [
                    self._expression_points(
                        argument,
                        context,
                        local_points,
                        heap_points,
                        call_string,
                    )
                    for argument in call.arguments
                ]
                receiver_points = (
                    self._expression_points(
                        call.receiver,
                        context,
                        local_points,
                        heap_points,
                        call_string,
                    )
                    if call.receiver
                    else set()
                )
                library_models = [
                    model
                    for model in self.jvm_model_pack.models
                    if model.matches(call, context.ast.language, receiver_points)
                ]
                for model in library_models:
                    library_returned = self._apply_library_model(
                        model,
                        call,
                        context,
                        statement,
                        argument_states,
                        receiver_points,
                        locals_taint,
                        local_points,
                        heap_taints,
                        heap_points,
                        flows,
                        call_string,
                        object_return_sites,
                    )
                    self._merge_traces(call_returns, library_returned)
                    if "return" in model.outputs:
                        internal_call_on_rhs = internal_call_on_rhs or self._call_in_expression(
                            call, rhs
                        )
                for target in targets:
                    target_context = self._contexts.get(target)
                    if target_context is None:
                        continue
                    target_call_string = self._next_call_string(call_string, context, call)
                    if not self._activate_context(active_contexts, target, target_call_string):
                        continue
                    internal_call_on_rhs = internal_call_on_rhs or self._call_in_expression(
                        call, rhs
                    )
                    for index, parameter in enumerate(target_context.definition.parameters):
                        if index >= len(argument_states):
                            break
                        propagated = self._append_step(
                            argument_states[index],
                            variable=parameter,
                            file_path=target_context.definition.file_path,
                            line=target_context.definition.line_start,
                            propagation_type="argument",
                            function=target_context.definition.qualified_name,
                            call_context=target_call_string,
                        )
                        target_parameter = (target, target_call_string, parameter)
                        if self._merge_traces(parameter_taints[target_parameter], propagated):
                            self._argument_events.add(
                                (context.node_id, target, parameter, call.line)
                            )
                        if index < len(argument_points):
                            parameter_points[target_parameter].update(argument_points[index])
                            carries_tainted_field = any(
                                traces
                                for object_id in argument_points[index]
                                for heap_key, traces in heap_taints.items()
                                if heap_key.startswith(f"heap:{object_id}:field:")
                            )
                            if carries_tainted_field:
                                self._argument_events.add(
                                    (context.node_id, target, parameter, call.line)
                                )
                    if call.receiver:
                        parameter_points[(target, target_call_string, "this")].update(
                            receiver_points
                        )
                    call_returned = self._append_step(
                        return_taints.get((target, target_call_string), {}),
                        variable=lhs or self._call_text(call),
                        file_path=context.definition.file_path,
                        line=call.line,
                        propagation_type="return",
                        function=context.definition.qualified_name,
                        call_context=call_string,
                    )
                    if call_returned:
                        self._return_events.add((target, context.node_id, call.line))
                        self._merge_traces(call_returns, call_returned)
                    returned_objects = return_points.get((target, target_call_string), set())
                    if returned_objects:
                        call_return_points.update(returned_objects)
                        for object_id in returned_objects:
                            object_return_sites[object_id] = (
                                lhs or self._call_text(call),
                                call.line,
                            )
                        self._object_return_events.add((target, context.node_id, call.line))

                sink_event = sink_by_call.get((call.file_path, call.line, call.column))
                if sink_event is not None:
                    self._record_sink_flows(
                        sink_event,
                        argument_states,
                        flows,
                        call_string,
                    )

            if assignment is not None and lhs is not None:
                allocation = self._allocation_type(rhs)
                if allocation:
                    object_id = (
                        f"allocation:{context.node_id}:{self._context_id(call_string)}:"
                        f"{statement.node_id}:{allocation}"
                    )
                    self._heap_objects.add(object_id)
                    self._write_points(
                        lhs,
                        {object_id},
                        context,
                        local_points,
                        heap_points,
                        call_string,
                        statement.line_start,
                    )
                elif internal_call_on_rhs and call_return_points:
                    self._write_points(
                        lhs,
                        call_return_points,
                        context,
                        local_points,
                        heap_points,
                        call_string,
                        statement.line_start,
                    )
                else:
                    alias_points = self._expression_points(
                        rhs,
                        context,
                        local_points,
                        heap_points,
                        call_string,
                    )
                    if alias_points:
                        self._write_points(
                            lhs,
                            alias_points,
                            context,
                            local_points,
                            heap_points,
                            call_string,
                            statement.line_start,
                        )

                if internal_call_on_rhs:
                    assigned = call_returns
                else:
                    assigned = self._expression_traces(
                        rhs,
                        context,
                        statement,
                        locals_taint,
                        local_points,
                        heap_taints,
                        heap_points,
                        call_string,
                        object_return_sites,
                        include_line_sources=True,
                    )
                    self._merge_traces(assigned, call_returns)
                sanitizer = self._sanitizer(rhs, context.ast)
                if sanitizer:
                    assigned = self._mark_sanitized(assigned, sanitizer)
                propagation_type = "field-store" if "." in lhs else "assignment"
                assigned = self._append_step(
                    assigned,
                    variable=lhs,
                    file_path=context.definition.file_path,
                    line=statement.line_start,
                    propagation_type=propagation_type,
                    function=context.definition.qualified_name,
                    call_context=call_string,
                )
                self._write_traces(
                    lhs,
                    assigned,
                    context,
                    locals_taint,
                    local_points,
                    heap_taints,
                    call_string,
                    statement.line_start,
                )

            return_expression = self._return_expression(statement.code)
            if return_expression is not None:
                returned_traces = self._expression_traces(
                    return_expression,
                    context,
                    statement,
                    locals_taint,
                    local_points,
                    heap_taints,
                    heap_points,
                    call_string,
                    object_return_sites,
                    include_line_sources=True,
                )
                self._merge_traces(returned_traces, call_returns)
                returned_traces = self._append_step(
                    returned_traces,
                    variable="<return>",
                    file_path=context.definition.file_path,
                    line=statement.line_start,
                    propagation_type="return",
                    function=context.definition.qualified_name,
                    call_context=call_string,
                )
                self._merge_traces(return_taints[(context.node_id, call_string)], returned_traces)
                returned_points = self._expression_points(
                    return_expression,
                    context,
                    local_points,
                    heap_points,
                    call_string,
                )
                returned_points.update(call_return_points)
                allocation = self._allocation_type(return_expression)
                if allocation:
                    object_id = (
                        f"allocation:{context.node_id}:{self._context_id(call_string)}:"
                        f"{statement.node_id}:return:{allocation}"
                    )
                    self._heap_objects.add(object_id)
                    returned_points.add(object_id)
                return_points[(context.node_id, call_string)].update(returned_points)

    def _apply_library_model(
        self,
        model: JvmLibraryModel,
        call: CallSite,
        context: _FunctionContext,
        statement: _Statement,
        argument_states: list[_TraceMap],
        receiver_points: set[str],
        locals_taint: dict[str, _TraceMap],
        local_points: dict[str, set[str]],
        heap_taints: dict[str, _TraceMap],
        heap_points: dict[str, set[str]],
        flows: dict[tuple[str, str, int, str, _CallString], TaintFlow],
        call_string: _CallString,
        object_return_sites: dict[str, tuple[str, int]],
    ) -> _TraceMap:
        self._library_applications.add(
            (model.id, context.node_id, call_string, call.line, call.column)
        )
        if model.role == "source":
            source = TaintSource(
                variable=self._call_text(call),
                file_path=call.file_path,
                line=call.line,
                source_type=model.source_type or "library_source",
                in_function=context.definition.qualified_name,
            )
            origin = self._origin_id(source)
            self._source_ids.add(origin)
            selected = {origin: self._source_trace(source)}
        elif model.role == "sink":
            sink = TaintSink(
                function=self._call_text(call),
                file_path=call.file_path,
                line=call.line,
                sink_type=model.sink_type or "library_sink",
                argument_index=model.argument_index,
                in_function=context.definition.qualified_name,
            )
            self._sink_ids.add((call.file_path, call.line, call.column, sink.sink_type))
            self._record_sink_flows(
                _SinkEvent(sink=sink, call=call),
                argument_states,
                flows,
                call_string,
            )
            return {}
        else:
            selected = {}
            for selector in model.inputs:
                if selector == "arguments":
                    for state in argument_states:
                        self._merge_traces(selected, state)
                elif selector == "receiver" and call.receiver:
                    receiver_state = self._expression_traces(
                        call.receiver,
                        context,
                        statement,
                        locals_taint,
                        local_points,
                        heap_taints,
                        heap_points,
                        call_string,
                        object_return_sites,
                        include_line_sources=True,
                    )
                    self._merge_traces(selected, receiver_state)
                elif selector.startswith("argument:"):
                    index = int(selector.partition(":")[2])
                    if index < len(argument_states):
                        self._merge_traces(selected, argument_states[index])

        propagated = self._append_step(
            selected,
            variable=model.id,
            file_path=call.file_path,
            line=call.line,
            propagation_type="library-summary",
            function=context.definition.qualified_name,
            call_context=call_string,
        )
        if model.role == "sanitizer":
            propagated = self._mark_sanitized_for(propagated, model.id, model.sanitizes)

        returned: _TraceMap = {}
        if "return" in model.outputs:
            self._merge_traces(returned, propagated)
        if "receiver" in model.outputs and call.receiver:
            receiver_state = self._expression_traces(
                call.receiver,
                context,
                statement,
                locals_taint,
                local_points,
                heap_taints,
                heap_points,
                call_string,
                object_return_sites,
                include_line_sources=True,
            )
            self._merge_traces(receiver_state, propagated)
            self._write_traces(
                call.receiver,
                receiver_state,
                context,
                locals_taint,
                local_points,
                heap_taints,
                call_string,
                statement.line_start,
            )
            self._heap_objects.update(receiver_points)
        return returned

    def _record_sink_flows(
        self,
        event: _SinkEvent,
        argument_states: list[_TraceMap],
        flows: dict[tuple[str, str, int, str, _CallString], TaintFlow],
        call_string: _CallString,
    ) -> None:
        index = event.sink.argument_index
        if index < 0 or index >= len(argument_states):
            return
        states = argument_states[index]
        for origin, trace in states.items():
            sanitized = trace.sanitized or event.sink.sink_type in trace.sanitized_for
            sink_step = TaintPropagation(
                variable=event.sink.function,
                file_path=event.sink.file_path,
                line=event.sink.line,
                propagation_type="sink",
                function=event.sink.in_function,
                call_context=list(call_string),
            )
            flow = TaintFlow(
                source=trace.source,
                sink=event.sink,
                path=[*trace.path, sink_step],
                sanitized=sanitized,
                sanitizer=trace.sanitizer if sanitized else None,
            )
            key = (
                origin,
                event.sink.file_path,
                event.sink.line,
                event.sink.sink_type,
                call_string,
            )
            existing = flows.get(key)
            if existing is None or self._flow_rank(flow) < self._flow_rank(existing):
                flows[key] = flow

    def _expression_traces(
        self,
        expression: str,
        context: _FunctionContext,
        statement: _Statement,
        locals_taint: dict[str, _TraceMap],
        local_points: dict[str, set[str]],
        heap_taints: dict[str, _TraceMap],
        heap_points: dict[str, set[str]],
        call_string: _CallString,
        object_return_sites: dict[str, tuple[str, int]],
        *,
        include_line_sources: bool,
    ) -> _TraceMap:
        traces: _TraceMap = {}
        for access in self._accesses(expression):
            for key in self._value_keys(access, context, local_points, heap_points, call_string):
                if key.startswith("local:"):
                    variable = key.rsplit(":", 1)[-1]
                    self._merge_traces(traces, locals_taint.get(variable, {}))
                else:
                    field_name = key.split(":field:", 1)[-1]
                    field_input = heap_taints.get(key, {})
                    base = access.split(".", 1)[0]
                    object_id = key.removeprefix("heap:").split(":field:", 1)[0]
                    return_site = object_return_sites.get(object_id)
                    if return_site is not None:
                        field_input = self._append_step(
                            field_input,
                            variable=return_site[0],
                            file_path=context.definition.file_path,
                            line=return_site[1],
                            propagation_type="return",
                            function=context.definition.qualified_name,
                            call_context=call_string,
                        )
                    if base in context.definition.parameters:
                        # Object identity crosses the call boundary even when
                        # the tainted value remains stored in one of its fields.
                        field_input = self._append_step(
                            field_input,
                            variable=base,
                            file_path=context.definition.file_path,
                            line=context.definition.line_start,
                            propagation_type="argument",
                            function=context.definition.qualified_name,
                            call_context=call_string,
                        )
                    field_traces = self._append_step(
                        field_input,
                        variable=access,
                        file_path=context.definition.file_path,
                        line=statement.line_start,
                        propagation_type="field-load",
                        function=context.definition.qualified_name,
                        call_context=call_string,
                    )
                    if field_traces:
                        self._field_reads.add((context.node_id, statement.line_start, field_name))
                    self._merge_traces(traces, field_traces)
        if include_line_sources:
            for line in range(statement.line_start, statement.line_end + 1):
                line_sources = self._source_traces.get((context.definition.file_path, line), {})
                matching = {
                    origin: trace
                    for origin, trace in line_sources.items()
                    if self._source_occurs_in_expression(trace.source.variable, expression)
                }
                self._merge_traces(traces, matching)
        return traces

    def _expression_points(
        self,
        expression: str,
        context: _FunctionContext,
        local_points: dict[str, set[str]],
        heap_points: dict[str, set[str]],
        call_string: _CallString,
    ) -> set[str]:
        points: set[str] = set()
        for access in self._accesses(expression):
            if "." not in access:
                points.update(local_points.get(access, set()))
                continue
            for key in self._value_keys(access, context, local_points, heap_points, call_string):
                if key.startswith("heap:"):
                    points.update(heap_points.get(key, set()))
        return points

    def _write_traces(
        self,
        lhs: str,
        traces: _TraceMap,
        context: _FunctionContext,
        locals_taint: dict[str, _TraceMap],
        local_points: dict[str, set[str]],
        heap_taints: dict[str, _TraceMap],
        call_string: _CallString,
        line: int,
    ) -> None:
        if "." not in lhs:
            # A local assignment is a strong, flow-sensitive update.
            locals_taint[lhs] = dict(traces)
            return
        keys = self._value_keys(lhs, context, local_points, {}, call_string)
        strong_update = len(keys) == 1 and keys[0].startswith("heap:allocation:")
        for key in keys:
            if not key.startswith("heap:"):
                continue
            if strong_update:
                heap_taints[key] = dict(traces)
                self._strong_update_events.add((context.node_id, line, lhs))
            else:
                self._merge_traces(heap_taints[key], traces)
            self._field_writes.add((context.node_id, line, lhs))

    def _write_points(
        self,
        lhs: str,
        points: set[str],
        context: _FunctionContext,
        local_points: dict[str, set[str]],
        heap_points: dict[str, set[str]],
        call_string: _CallString,
        line: int,
    ) -> None:
        if "." not in lhs:
            local_points[lhs] = set(points)
            return
        keys = self._value_keys(lhs, context, local_points, heap_points, call_string)
        strong_update = len(keys) == 1 and keys[0].startswith("heap:allocation:")
        for key in keys:
            if key.startswith("heap:"):
                if strong_update:
                    heap_points[key] = set(points)
                    self._strong_update_events.add((context.node_id, line, lhs))
                else:
                    heap_points[key].update(points)

    def _value_keys(
        self,
        access: str,
        context: _FunctionContext,
        local_points: dict[str, set[str]],
        heap_points: dict[str, set[str]],
        call_string: _CallString,
    ) -> list[str]:
        parts = access.split(".")
        if len(parts) == 1:
            return [f"local:{context.node_id}:{access}"]
        base = parts[0]
        fields = ".".join(parts[1:])
        objects = set(local_points.get(base, set()))
        if not objects:
            objects.add(f"unknown:{context.node_id}:{self._context_id(call_string)}:{base}")
        keys = [f"heap:{object_id}:field:{fields}" for object_id in sorted(objects)]
        # If the base itself is stored in a field, preserve any object identity
        # learned for that field on subsequent nested dereferences.
        for key in list(keys):
            objects.update(heap_points.get(key, set()))
        return keys

    def _resolve_call_targets(self, context: _FunctionContext, call: CallSite) -> list[str]:
        exact = self._edge_targets.get(
            (context.node_id, call.file_path, call.line, call.column), set()
        )
        if exact:
            return sorted(target for target in exact if target in self._contexts)
        by_line = self._edge_targets.get((context.node_id, call.file_path, call.line, -1), set())
        if by_line:
            return sorted(target for target in by_line if target in self._contexts)

        # Compiler-index path: caller occurrence -> canonical symbol -> concrete
        # definition function.  The semantic overlay preserves occurrence lines.
        semantic_targets: set[str] = set()
        if self._program_graph is not None and context.node_id in self._program_graph:
            for _, symbol, attributes in self._program_graph.out_edges(context.node_id, data=True):
                if (
                    attributes.get("kind") != "symbol-reference"
                    or int(attributes.get("line", 0) or 0) != call.line
                ):
                    continue
                for _, target, definition in self._program_graph.out_edges(symbol, data=True):
                    if definition.get("kind") == "resolved-definition" and target in self._contexts:
                        semantic_targets.add(str(target))
        if semantic_targets:
            return sorted(semantic_targets)

        candidates = self._functions_by_name.get(call.callee, [])
        return candidates if len(candidates) == 1 else []

    def _next_call_string(
        self,
        current: _CallString,
        context: _FunctionContext,
        call: CallSite,
    ) -> _CallString:
        module = context.ast.module_path or Path(call.file_path).name
        call_site = f"{context.node_id}@{module}:{call.line}:{call.column}:{call.callee}"
        return (*current, call_site)[-self.context_depth :]

    def _activate_context(
        self,
        active_contexts: set[tuple[str, _CallString]],
        function_id: str,
        call_string: _CallString,
    ) -> bool:
        key = (function_id, call_string)
        if key in active_contexts:
            return True
        if len(active_contexts) >= self.max_contexts:
            self.summary.truncated = True
            warning = f"global taint hit the {self.max_contexts}-context bound"
            if warning not in self.summary.warnings:
                self.summary.warnings.append(warning)
            return False
        active_contexts.add(key)
        return True

    @staticmethod
    def _context_id(call_string: _CallString) -> str:
        if not call_string:
            return "root"
        encoded = "|".join(call_string).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:12]

    def _is_entry_point(self, context: _FunctionContext) -> bool:
        if self._call_graph is not None and context.node_id in self._call_graph:
            node = self._call_graph.nodes[context.node_id].get("data")
            if node is not None and bool(getattr(node, "is_entry_point", False)):
                return True
        return any(
            marker in decorator
            for decorator in context.definition.decorators
            for marker in self._ROUTE_MARKERS
        )

    @classmethod
    def _assignment(cls, code: str) -> tuple[str, str] | None:
        match = cls._ASSIGNMENT.search(code)
        if match is None:
            return None
        left = code[: match.start()]
        right = code[match.end() :]
        candidates = cls._ACCESS.findall(left)
        if not candidates:
            return None
        lhs = candidates[-1]
        return lhs, right.strip().rstrip(";")

    @classmethod
    def _allocation_type(cls, expression: str) -> str | None:
        java = cls._NEW_JAVA.search(expression)
        if java:
            return java.group(1)
        kotlin = cls._NEW_KOTLIN.search(expression)
        if kotlin:
            return kotlin.group(1)
        return None

    @classmethod
    def _return_expression(cls, code: str) -> str | None:
        match = cls._RETURN.search(code)
        return match.group("value").strip().rstrip(";") if match else None

    @classmethod
    def _accesses(cls, expression: str) -> list[str]:
        interpolated: list[str] = []
        for fragment in re.findall(r"\{([^{}]+)\}", expression):
            interpolated.extend(cls._ACCESS.findall(fragment))
        interpolated.extend(re.findall(r"\$(?!\{)([A-Za-z_$][\w$]*)", expression))
        scrubbed = re.sub(
            r"(['\"])(?:\\.|(?!\1).)*\1",
            lambda match: " " * len(match.group(0)),
            expression,
            flags=re.DOTALL,
        )
        accesses: list[str] = [
            value for value in interpolated if value not in cls._KEYWORDS and not value[0].isupper()
        ]
        for match in cls._ACCESS.finditer(scrubbed):
            value = match.group(0)
            if value in cls._KEYWORDS or value[0].isupper():
                continue
            suffix = scrubbed[match.end() :].lstrip()
            if suffix.startswith("("):
                if "." not in value:
                    continue
                value = value.rsplit(".", 1)[0]
            if value and value not in accesses:
                accesses.append(value)
        return accesses

    def _sanitizer(self, expression: str, ast: FileAST) -> str | None:
        lowered = expression.lower()
        for sanitizer in self.config.sanitizers.get(ast.language, []):
            if sanitizer.lower() in lowered:
                return str(sanitizer)
        return None

    @staticmethod
    def _mark_sanitized(traces: _TraceMap, sanitizer: str) -> _TraceMap:
        return {
            origin: _Trace(
                source=trace.source,
                path=trace.path,
                sanitized=True,
                sanitizer=sanitizer,
                sanitized_for=frozenset({"*"}),
            )
            for origin, trace in traces.items()
        }

    @staticmethod
    def _mark_sanitized_for(
        traces: _TraceMap,
        sanitizer: str,
        sink_types: list[str],
    ) -> _TraceMap:
        return {
            origin: _Trace(
                source=trace.source,
                path=trace.path,
                sanitized=trace.sanitized,
                sanitizer=sanitizer,
                sanitized_for=trace.sanitized_for | frozenset(sink_types),
            )
            for origin, trace in traces.items()
        }

    @staticmethod
    def _call_text(call: CallSite) -> str:
        return f"{call.receiver}.{call.callee}" if call.receiver else call.callee

    @staticmethod
    def _pattern_matches(pattern: str, text: str) -> bool:
        normalized = pattern.removesuffix("(")
        if pattern in text or normalized == text:
            return True
        return bool(
            re.search(
                rf"(?<![A-Za-z0-9_$]){re.escape(normalized)}"
                r"(?![A-Za-z0-9_$])",
                text,
            )
        )

    @classmethod
    def _call_matches_pattern(cls, pattern: str, call: CallSite) -> bool:
        call_text = cls._call_text(call)
        if cls._pattern_matches(pattern, call_text):
            return True
        normalized = pattern.removesuffix("(")
        if "." not in normalized:
            return cls._pattern_matches(normalized, call.callee)
        receiver_pattern, method_pattern = normalized.rsplit(".", 1)
        return (
            call.callee == method_pattern
            and call.receiver is not None
            and cls._pattern_matches(receiver_pattern, call.receiver)
        )

    @staticmethod
    def _source_occurs_in_expression(source_expression: str, expression: str) -> bool:
        compact_source = re.sub(r"\s+", "", source_expression).removesuffix("(")
        compact_expression = re.sub(r"\s+", "", expression)
        return compact_source in compact_expression

    @classmethod
    def _call_in_expression(cls, call: CallSite, expression: str) -> bool:
        text = cls._call_text(call)
        return f"{text}(" in re.sub(r"\s+", "", expression)

    @staticmethod
    def _statement_for_call(statements: list[_Statement], call: CallSite) -> _Statement | None:
        candidates = [
            statement
            for statement in statements
            if statement.line_start <= call.line <= statement.line_end
        ]
        if not candidates:
            return None
        return min(
            candidates,
            key=lambda statement: (
                statement.line_end - statement.line_start,
                len(statement.code),
            ),
        )

    def _source_trace(self, source: TaintSource) -> _Trace:
        return _Trace(
            source=source,
            path=(
                TaintPropagation(
                    variable=source.variable,
                    file_path=source.file_path,
                    line=source.line,
                    propagation_type="source",
                    function=source.in_function,
                ),
            ),
        )

    def _line_has_source_type(self, file_path: str, line: int, source_type: str) -> bool:
        return any(
            trace.source.source_type == source_type
            for trace in self._source_traces.get((file_path, line), {}).values()
        )

    @staticmethod
    def _origin_id(source: TaintSource) -> str:
        return (
            f"{source.file_path}:{source.line}:{source.source_type}:"
            f"{source.variable}:{source.in_function or ''}"
        )

    @staticmethod
    def _append_step(
        traces: _TraceMap,
        *,
        variable: str,
        file_path: str,
        line: int,
        propagation_type: str,
        function: str | None,
        call_context: _CallString = (),
    ) -> _TraceMap:
        result: _TraceMap = {}
        for origin, trace in traces.items():
            step = TaintPropagation(
                variable=variable,
                file_path=file_path,
                line=line,
                propagation_type=propagation_type,
                function=function,
                call_context=list(call_context),
            )
            if trace.path and trace.path[-1] == step:
                result[origin] = trace
            else:
                result[origin] = _Trace(
                    source=trace.source,
                    path=(*trace.path, step),
                    sanitized=trace.sanitized,
                    sanitizer=trace.sanitizer,
                    sanitized_for=trace.sanitized_for,
                )
        return result

    @classmethod
    def _merge_traces(cls, target: _TraceMap, incoming: _TraceMap) -> bool:
        changed = False
        for origin, candidate in incoming.items():
            current = target.get(origin)
            if current is None or cls._trace_rank(candidate) < cls._trace_rank(current):
                target[origin] = candidate
                changed = True
        return changed

    @staticmethod
    def _trace_rank(trace: _Trace) -> tuple[int, int]:
        # An unsanitized path dominates a sanitized path for the same origin.
        return (1 if trace.sanitized or trace.sanitized_for else 0, len(trace.path))

    @staticmethod
    def _flow_rank(flow: TaintFlow) -> tuple[int, int]:
        return (1 if flow.sanitized else 0, len(flow.path))

    @staticmethod
    def _line_from_key(traces: _TraceMap) -> int:
        lines = [trace.path[-1].line for trace in traces.values() if trace.path]
        return min(lines) if lines else 0

    @classmethod
    def _state_signature(
        cls,
        parameter_taints: dict[tuple[str, _CallString, str], _TraceMap],
        parameter_points: dict[tuple[str, _CallString, str], set[str]],
        return_taints: dict[tuple[str, _CallString], _TraceMap],
        return_points: dict[tuple[str, _CallString], set[str]],
        heap_taints: dict[str, _TraceMap],
        heap_points: dict[str, set[str]],
        active_contexts: set[tuple[str, _CallString]],
    ) -> tuple[Any, ...]:
        def trace_signature(mapping: dict[Any, _TraceMap]) -> tuple[Any, ...]:
            return tuple(
                sorted(
                    (
                        str(key),
                        tuple(
                            sorted(
                                (
                                    origin,
                                    trace.sanitized,
                                    trace.sanitizer or "",
                                    tuple(sorted(trace.sanitized_for)),
                                    len(trace.path),
                                )
                                for origin, trace in traces.items()
                            )
                        ),
                    )
                    for key, traces in mapping.items()
                    if traces
                )
            )

        def points_signature(mapping: dict[Any, set[str]]) -> tuple[Any, ...]:
            return tuple(
                sorted(
                    (str(key), tuple(sorted(points))) for key, points in mapping.items() if points
                )
            )

        return (
            trace_signature(parameter_taints),
            points_signature(parameter_points),
            trace_signature(return_taints),
            points_signature(return_points),
            trace_signature(heap_taints),
            points_signature(heap_points),
            tuple(sorted(active_contexts)),
        )
