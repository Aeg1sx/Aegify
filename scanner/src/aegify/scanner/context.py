"""Context analyzer for detecting defense mechanisms (auth, sanitizers, validation)."""

from __future__ import annotations

import logging
from pathlib import Path

import networkx as nx

from aegify.config import ContextConfig
from aegify.graph_types import CodeGraph
from aegify.models import (
    CallChainStep,
    DefenseContext,
    FileAST,
    FunctionDef,
    TaintFlow,
)

logger = logging.getLogger(__name__)


class ContextAnalyzer:
    """Analyzes the execution context around potential vulnerabilities
    to detect defense mechanisms that reduce or eliminate risk."""

    def __init__(self, config: ContextConfig | None = None) -> None:
        self.config = config or ContextConfig()
        self._function_index: dict[str, FunctionDef] = {}
        self._file_asts: dict[str, FileAST] = {}

    def load(self, file_asts: list[FileAST]) -> None:
        """Index all file ASTs for context lookup."""
        for ast in file_asts:
            self._file_asts[ast.file_path] = ast
            for func in ast.functions:
                self._function_index[func.qualified_name] = func
            for cls in ast.classes:
                for method in cls.methods:
                    self._function_index[method.qualified_name] = method

    def analyze_defense(
        self,
        taint_flow: TaintFlow,
        call_graph: CodeGraph,
    ) -> DefenseContext:
        """Analyze the defense context for a taint flow."""
        context = DefenseContext()

        # Check if the flow is already marked as sanitized
        if taint_flow.sanitized:
            context.sanitizer_present = True
            context.sanitizer_function = taint_flow.sanitizer
            return context

        # Get the function containing the sink
        sink_func = taint_flow.sink.in_function
        if not sink_func:
            return context

        # Check auth decorators on the containing function
        self._check_auth_decorators(sink_func, context)

        # Check auth in the call chain from entry points
        self._check_call_chain_auth(sink_func, call_graph, context)

        # Check for parameterized queries
        if taint_flow.sink.sink_type == "sql_query":
            self._check_parameterized_query(taint_flow, context)

        # Check input validation in the enclosing function
        self._check_input_validation(taint_flow, context)

        return context

    def get_call_chain_steps(
        self,
        entry_point: str,
        sink_func: str,
        call_graph: CodeGraph,
    ) -> list[CallChainStep]:
        """Build human-readable call chain steps from entry to sink."""
        chain: list[CallChainStep] = []
        try:
            path = nx.shortest_path(call_graph, entry_point, sink_func)
        except nx.NodeNotFound, nx.NetworkXNoPath:
            return chain

        for node_name in path:
            func = self._function_index.get(node_name)
            if func:
                # Read code snippet
                snippet = self._get_code_snippet(func.file_path, func.line_start)
                chain.append(
                    CallChainStep(
                        file_path=func.file_path,
                        function=func.qualified_name,
                        line=func.line_start,
                        code_snippet=snippet,
                    )
                )
        return chain

    def _check_auth_decorators(self, func_name: str, context: DefenseContext) -> None:
        """Check if the function has auth-related decorators."""
        func = self._function_index.get(func_name)
        if not func:
            return

        for decorator in func.decorators:
            for pattern in self.config.auth_patterns:
                if pattern in decorator:
                    context.auth_present = True
                    context.auth_decorator = decorator
                    context.details["auth_type"] = "decorator"
                    return

    def _check_call_chain_auth(
        self, sink_func: str, call_graph: CodeGraph, context: DefenseContext
    ) -> None:
        """Check if any function in the call chain has auth checks."""
        if context.auth_present:
            return

        # Walk up the call chain from sink
        callers = []
        try:
            callers = list(nx.ancestors(call_graph, sink_func))
        except nx.NetworkXError:
            return

        for caller in callers:
            func = self._function_index.get(caller)
            if not func:
                continue

            for decorator in func.decorators:
                for pattern in self.config.auth_patterns:
                    if pattern in decorator:
                        context.auth_present = True
                        context.auth_decorator = decorator
                        context.details["auth_type"] = "call_chain"
                        context.details["auth_function"] = caller
                        return

            # Check for auth-related calls inside the function
            ast = self._file_asts.get(func.file_path)
            if ast:
                for call in ast.calls:
                    if call.in_function != func.name:
                        continue
                    call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
                    for pattern in self.config.auth_patterns:
                        if pattern.lstrip("@") in call_text:
                            context.auth_present = True
                            context.auth_decorator = call_text
                            context.details["auth_type"] = "function_call"
                            context.details["auth_function"] = caller
                            return

    def _check_parameterized_query(self, taint_flow: TaintFlow, context: DefenseContext) -> None:
        """Check if a SQL sink uses parameterized queries."""
        ast = self._file_asts.get(taint_flow.sink.file_path)
        if not ast:
            return

        for call in ast.calls:
            if call.line != taint_flow.sink.line:
                continue
            # Check if args contain placeholders (not string concat)
            for arg in call.arguments:
                if any(p in arg for p in ["?", "%s", "$1", ":param", "%(", "${}"]):
                    context.parameterized_query = True
                    context.details["query_type"] = "parameterized"
                    return

        # Check for prepared statement patterns
        for call in ast.calls:
            if call.line < taint_flow.sink.line and call.in_function == taint_flow.sink.in_function:
                call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
                if "prepare" in call_text.lower():
                    context.parameterized_query = True
                    context.details["query_type"] = "prepared_statement"
                    return

    def _check_input_validation(self, taint_flow: TaintFlow, context: DefenseContext) -> None:
        """Check for input validation between source and sink."""
        ast = self._file_asts.get(taint_flow.source.file_path)
        if not ast:
            return

        for call in ast.calls:
            if not (taint_flow.source.line <= call.line <= taint_flow.sink.line):
                continue
            if call.in_function != taint_flow.source.in_function:
                continue

            call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
            for pattern in self.config.sanitizer_patterns:
                if pattern.lower() in call_text.lower():
                    context.sanitizer_present = True
                    context.sanitizer_function = call_text
                    context.input_validation = True
                    return

    def _get_code_snippet(self, file_path: str, line: int, context_lines: int = 2) -> str:
        """Read a code snippet from a file."""
        try:
            path = Path(file_path)
            lines = path.read_text().splitlines()
            start = max(0, line - 1 - context_lines)
            end = min(len(lines), line + context_lines)
            return "\n".join(lines[start:end])
        except OSError:
            return ""
