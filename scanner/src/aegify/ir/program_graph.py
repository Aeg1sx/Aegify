"""AST-structured CFG, reaching-def DFG, SSA-phi, and points-to overlays."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import networkx as nx
from tree_sitter import Node

from aegify.graph_types import ProgramGraph
from aegify.models import FileAST, FunctionDef, ProgramGraphSummary
from aegify.scanner.ast_parser import _get_parser


@dataclass
class ProgramGraphBundle:
    """In-memory graph and result summary."""

    graph: ProgramGraph
    summary: ProgramGraphSummary


class ProgramGraphBuilder:
    """Build a language-neutral graph from tree-sitter function bodies."""

    _FUNCTION_TYPES = {
        "function_definition",
        "function_declaration",
        "method_definition",
        "method_declaration",
        "constructor_declaration",
        "function_item",
    }
    _BLOCK_TYPES = {
        "block",
        "class_body",
        "function_body",
        "statement_block",
    }
    _IF_TYPES = {"if_statement", "if_expression"}
    _SWITCH_TYPES = {"switch_expression", "switch_statement", "when_expression"}
    _TRY_TYPES = {
        "try_expression",
        "try_statement",
        "try_with_resources_statement",
    }
    _CATCH_TYPES = {"catch_block", "catch_clause", "except_clause"}
    _FINALLY_TYPES = {"finally_block", "finally_clause"}
    _TRY_ELSE_TYPES = {"else_clause"}
    _LOOP_TYPES = {
        "do_statement",
        "for_in_statement",
        "for_statement",
        "while_statement",
        "while_expression",
    }
    _FUNCTION_TERMINAL_TYPES = {
        "raise_statement",
        "return_statement",
        "throw_expression",
        "throw_statement",
    }
    _KEYWORDS = {
        "as",
        "async",
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "def",
        "do",
        "else",
        "false",
        "final",
        "finally",
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
        "suspend",
        "throw",
        "true",
        "try",
        "val",
        "var",
        "void",
        "when",
        "while",
    }
    _IDENTIFIER = re.compile(r"\b[A-Za-z_$][\w$]*\b")
    _DECLARATION = re.compile(
        r"\b(?:val|var|let|const|final)\s+([A-Za-z_$][\w$]*)"
        r"|\b[A-Za-z_$][\w.$<>?,\[\]]*\s+([a-zA-Z_$][\w$]*)\s*="
    )
    _ASSIGNMENT = re.compile(r"(?<![=!<>])\b([A-Za-z_$][\w$]*)\s*=(?!=)")
    _JAVA_DECLARATION = re.compile(
        r"^\s*(?:final\s+)?[A-Za-z_$][\w.$<>?,\[\]]*\s+"
        r"([A-Za-z_$][\w$]*)\s*(?:[;=])"
    )
    _JAVA_ALLOCATION = re.compile(r"\bnew\s+([A-Z][\w.$]*)\s*\(")
    _KOTLIN_ALLOCATION = re.compile(
        r"\b(?:val|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=]+)?\s*=\s*"
        r"([A-Z][\w.$]*)\s*\("
    )
    _ALIAS = re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*[;\n}]?$")

    def build(self, file_asts: list[FileAST]) -> ProgramGraphBundle:
        graph: ProgramGraph = nx.MultiDiGraph()
        summary = ProgramGraphSummary(enabled=True)
        for ast in file_asts:
            try:
                source = Path(ast.file_path).read_bytes()
            except OSError as error:
                summary.warnings.append(f"{ast.file_path}: {error}")
                continue
            tree = _get_parser(ast.language).parse(source)
            definitions = self._function_definitions(ast)
            for function_node in self._walk_functions(tree.root_node):
                function = self._match_function(function_node, source, definitions)
                if function is None:
                    continue
                self._build_function(graph, ast, function, function_node, source)
                summary.functions += 1

        self._build_data_overlays(graph, summary)
        summary.cfg_nodes = sum(
            1 for _, data in graph.nodes(data=True) if data.get("kind") == "statement"
        )
        summary.cfg_edges = sum(
            1 for _, _, data in graph.edges(data=True) if data.get("overlay") == "cfg"
        )
        summary.branch_edges = sum(
            1
            for _, _, data in graph.edges(data=True)
            if data.get("kind")
            in {
                "case",
                "default",
                "false",
                "fallthrough",
                "loop-back",
                "no-match",
                "true",
            }
        )
        summary.exception_edges = sum(
            1
            for _, _, data in graph.edges(data=True)
            if data.get("kind") in {"exception", "uncaught-exception", "exception-dispatch"}
        )
        summary.finally_edges = sum(
            1 for _, _, data in graph.edges(data=True) if "finally" in str(data.get("kind", ""))
        )
        summary.switch_edges = sum(
            1
            for _, _, data in graph.edges(data=True)
            if data.get("kind") in {"case", "default", "fallthrough", "no-match"}
        )
        summary.dfg_edges = sum(
            1 for _, _, data in graph.edges(data=True) if data.get("overlay") == "dfg"
        )
        summary.ssa_phi_nodes = sum(
            1 for _, data in graph.nodes(data=True) if data.get("kind") == "ssa-phi"
        )
        summary.points_to_edges = sum(
            1 for _, _, data in graph.edges(data=True) if data.get("kind") == "points-to"
        )
        summary.alias_edges = sum(
            1 for _, _, data in graph.edges(data=True) if data.get("kind") == "alias"
        )
        summary.data_state_nodes = sum(
            1 for _, data in graph.nodes(data=True) if data.get("kind") == "data-state"
        )
        summary.transformation_edges = sum(
            1 for _, _, data in graph.edges(data=True) if data.get("kind") == "transforms"
        )
        return ProgramGraphBundle(graph, summary)

    @staticmethod
    def _function_definitions(ast: FileAST) -> list[FunctionDef]:
        unique: dict[str, FunctionDef] = {}
        for function in ast.functions:
            key = function.symbol_id or f"{function.qualified_name}:{function.line_start}"
            unique[key] = function
        return list(unique.values())

    def _walk_functions(self, root: Node) -> list[Node]:
        result: list[Node] = []
        pending = [root]
        while pending:
            node = pending.pop()
            if node.type in self._FUNCTION_TYPES:
                result.append(node)
            pending.extend(reversed(node.named_children))
        return result

    def _match_function(
        self,
        node: Node,
        source: bytes,
        definitions: list[FunctionDef],
    ) -> FunctionDef | None:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            name_node = next(
                (
                    child
                    for child in node.named_children
                    if child.type in {"identifier", "simple_identifier"}
                ),
                None,
            )
        name = self._text(name_node, source) if name_node is not None else ""
        line = node.start_point[0] + 1
        exact = [
            function
            for function in definitions
            if function.name == name and function.line_start == line
        ]
        if len(exact) == 1:
            return exact[0]
        candidates = [function for function in definitions if function.name == name]
        return candidates[0] if len(candidates) == 1 else None

    def _build_function(
        self,
        graph: ProgramGraph,
        ast: FileAST,
        function: FunctionDef,
        node: Node,
        source: bytes,
    ) -> None:
        function_id = function.symbol_id or function.qualified_name
        relative_file = ast.module_path or ast.file_path
        file_id = (
            f"repo:{ast.repository_id}:file:{relative_file}"
            if ast.repository_id
            else f"file:{relative_file}"
        )
        entry = f"{function_id}::cfg:entry"
        exit_node = f"{function_id}::cfg:exit"
        graph.add_node(
            function_id,
            kind="function",
            file_path=ast.module_path or ast.file_path,
            repository_id=ast.repository_id,
            line=function.line_start,
        )
        graph.add_node(
            file_id,
            kind="file",
            file_path=relative_file,
            repository_id=ast.repository_id,
        )
        graph.add_edge(
            function_id,
            file_id,
            kind="declared-in",
            overlay="semantic",
            confidence=1.0,
        )
        graph.add_edge(
            file_id,
            function_id,
            kind="declares",
            overlay="semantic",
            confidence=1.0,
        )
        graph.add_node(
            entry,
            kind="entry",
            function=function_id,
            definitions=list(function.parameters),
            uses=[],
        )
        graph.add_node(exit_node, kind="exit", function=function_id, definitions=[], uses=[])
        graph.add_edge(function_id, entry, kind="contains", overlay="ast")

        body = node.child_by_field_name("body")
        if body is None:
            body = next(
                (child for child in node.named_children if child.type in self._BLOCK_TYPES),
                None,
            )
        statements = self._statements(body) if body is not None else []
        tails = self._emit_sequence(
            graph,
            ast,
            function_id,
            statements,
            [(entry, "next")],
            exit_node,
            source,
        )
        for tail, edge_kind in tails:
            graph.add_edge(tail, exit_node, kind=edge_kind, overlay="cfg")

    def _emit_sequence(
        self,
        graph: ProgramGraph,
        ast: FileAST,
        function_id: str,
        statements: list[Node],
        incoming: list[tuple[str, str]],
        exit_node: str,
        source: bytes,
        break_target: str | None = None,
        continue_target: str | None = None,
        terminal_target: str | None = None,
    ) -> list[tuple[str, str]]:
        tails = incoming
        for statement in statements:
            statement_id = self._statement_id(function_id, statement)
            text = self._text(statement, source)
            fact_text = text
            if statement.type in self._IF_TYPES | self._LOOP_TYPES | self._SWITCH_TYPES:
                condition = statement.child_by_field_name("condition")
                if condition is not None:
                    fact_text = self._text(condition, source)
            facts = self._data_facts(fact_text)
            graph.add_node(
                statement_id,
                kind="statement",
                syntax_kind=statement.type,
                function=function_id,
                repository_id=ast.repository_id,
                file_path=ast.module_path or ast.file_path,
                line_start=statement.start_point[0] + 1,
                line_end=statement.end_point[0] + 1,
                code=text[:1000],
                **facts,
            )
            graph.add_edge(function_id, statement_id, kind="contains", overlay="ast")
            for predecessor, edge_kind in tails:
                graph.add_edge(
                    predecessor,
                    statement_id,
                    kind=edge_kind,
                    overlay="cfg",
                )

            if statement.type in self._TRY_TYPES:
                tails = self._emit_try(
                    graph,
                    ast,
                    function_id,
                    statement,
                    statement_id,
                    exit_node,
                    source,
                    break_target,
                    continue_target,
                    terminal_target,
                )
            elif statement.type in self._SWITCH_TYPES:
                tails = self._emit_switch(
                    graph,
                    ast,
                    function_id,
                    statement,
                    statement_id,
                    exit_node,
                    source,
                    continue_target,
                    terminal_target,
                )
            elif statement.type in self._IF_TYPES:
                consequence = statement.child_by_field_name("consequence")
                alternative = statement.child_by_field_name("alternative")
                if consequence is None:
                    blocks = [
                        child
                        for child in statement.named_children
                        if child.type in self._BLOCK_TYPES
                    ]
                    consequence = blocks[0] if blocks else None
                    alternative = blocks[1] if len(blocks) > 1 else alternative
                then_tails = self._emit_sequence(
                    graph,
                    ast,
                    function_id,
                    self._statements(consequence),
                    [(statement_id, "true")],
                    exit_node,
                    source,
                    break_target,
                    continue_target,
                    terminal_target,
                )
                else_tails = (
                    self._emit_sequence(
                        graph,
                        ast,
                        function_id,
                        self._statements(alternative),
                        [(statement_id, "false")],
                        exit_node,
                        source,
                        break_target,
                        continue_target,
                        terminal_target,
                    )
                    if alternative is not None
                    else [(statement_id, "false")]
                )
                tails = then_tails + else_tails
            elif statement.type in self._LOOP_TYPES:
                body = statement.child_by_field_name("body")
                loop_exit = f"{statement_id}::loop-exit"
                graph.add_node(
                    loop_exit,
                    kind="control-join",
                    function=function_id,
                    definitions=[],
                    uses=[],
                )
                graph.add_edge(
                    statement_id,
                    loop_exit,
                    kind="false",
                    overlay="cfg",
                )
                loop_tails = self._emit_sequence(
                    graph,
                    ast,
                    function_id,
                    self._statements(body),
                    [(statement_id, "true")],
                    exit_node,
                    source,
                    loop_exit,
                    statement_id,
                    terminal_target,
                )
                for loop_tail, _ in loop_tails:
                    graph.add_edge(
                        loop_tail,
                        statement_id,
                        kind="loop-back",
                        overlay="cfg",
                    )
                tails = [(loop_exit, "next")]
            elif statement.type == "break_statement" and break_target:
                graph.add_edge(
                    statement_id,
                    break_target,
                    kind="break",
                    overlay="cfg",
                )
                tails = []
            elif statement.type == "continue_statement" and continue_target:
                graph.add_edge(
                    statement_id,
                    continue_target,
                    kind="continue",
                    overlay="cfg",
                )
                tails = []
            elif statement.type in self._FUNCTION_TERMINAL_TYPES:
                target = terminal_target or exit_node
                graph.add_edge(
                    statement_id,
                    target,
                    kind="terminal-finally" if terminal_target else "terminal",
                    overlay="cfg",
                )
                tails = []
            else:
                tails = [(statement_id, "next")]
        return tails

    def _emit_try(
        self,
        graph: ProgramGraph,
        ast: FileAST,
        function_id: str,
        statement: Node,
        statement_id: str,
        exit_node: str,
        source: bytes,
        break_target: str | None,
        continue_target: str | None,
        terminal_target: str | None,
    ) -> list[tuple[str, str]]:
        body = statement.child_by_field_name("body")
        if body is None:
            body = next(
                (child for child in statement.named_children if child.type in self._BLOCK_TYPES),
                None,
            )
        catches = [child for child in statement.named_children if child.type in self._CATCH_TYPES]
        finally_clause = next(
            (child for child in statement.named_children if child.type in self._FINALLY_TYPES),
            None,
        )
        else_clause = next(
            (child for child in statement.named_children if child.type in self._TRY_ELSE_TYPES),
            None,
        )
        try_exit = f"{statement_id}::try-exit"
        graph.add_node(
            try_exit,
            kind="control-join",
            function=function_id,
            definitions=[],
            uses=[],
        )
        finally_entry = f"{statement_id}::finally-entry" if finally_clause else None
        if finally_entry:
            graph.add_node(
                finally_entry,
                kind="control-join",
                function=function_id,
                definitions=[],
                uses=[],
            )

        before = set(graph.nodes)
        body_tails = self._emit_sequence(
            graph,
            ast,
            function_id,
            self._statements(body),
            [(statement_id, "try")],
            exit_node,
            source,
            break_target,
            continue_target,
            finally_entry or terminal_target,
        )
        body_statements = {
            node
            for node in set(graph.nodes) - before
            if graph.nodes[node].get("kind") == "statement"
        }
        catch_tails: list[tuple[str, str]] = []
        for index, catch in enumerate(catches):
            catch_entry = f"{statement_id}::catch-entry:{index}"
            graph.add_node(
                catch_entry,
                kind="control-join",
                function=function_id,
                definitions=[],
                uses=[],
            )
            graph.add_edge(
                statement_id,
                catch_entry,
                kind="exception-dispatch",
                overlay="cfg",
                fidelity="source-conservative",
            )
            for body_statement in body_statements:
                graph.add_edge(
                    body_statement,
                    catch_entry,
                    kind="exception",
                    overlay="cfg",
                    fidelity="source-conservative",
                )
            catch_body = catch.child_by_field_name("body")
            if catch_body is None:
                catch_body = next(
                    (
                        child
                        for child in reversed(catch.named_children)
                        if child.type in self._BLOCK_TYPES
                    ),
                    None,
                )
            catch_tails.extend(
                self._emit_sequence(
                    graph,
                    ast,
                    function_id,
                    self._statements(catch_body),
                    [(catch_entry, "catch")],
                    exit_node,
                    source,
                    break_target,
                    continue_target,
                    finally_entry or terminal_target,
                )
            )

        terminal_or_uncaught = False
        if not catches:
            exceptional_target = finally_entry or terminal_target or exit_node
            for body_statement in body_statements:
                graph.add_edge(
                    body_statement,
                    exceptional_target,
                    kind="uncaught-exception",
                    overlay="cfg",
                    fidelity="source-conservative",
                )
            terminal_or_uncaught = bool(body_statements)

        normal_tails = body_tails
        if else_clause is not None:
            else_body = next(
                (child for child in else_clause.named_children if child.type in self._BLOCK_TYPES),
                None,
            )
            normal_tails = self._emit_sequence(
                graph,
                ast,
                function_id,
                self._statements(else_body),
                normal_tails,
                exit_node,
                source,
                break_target,
                continue_target,
                finally_entry or terminal_target,
            )

        terminal_or_uncaught = terminal_or_uncaught or bool(
            finally_entry
            and any(
                data.get("kind") == "terminal-finally"
                for _, _, data in graph.in_edges(finally_entry, data=True)
            )
        )
        combined_tails = normal_tails + catch_tails
        if finally_clause is None or finally_entry is None:
            for tail, _ in combined_tails:
                graph.add_edge(
                    tail,
                    try_exit,
                    kind="try-complete",
                    overlay="cfg",
                )
            return [(try_exit, "next")]

        for tail, _ in combined_tails:
            graph.add_edge(
                tail,
                finally_entry,
                kind="finally",
                overlay="cfg",
            )
        finally_body = next(
            (child for child in finally_clause.named_children if child.type in self._BLOCK_TYPES),
            None,
        )
        finally_tails = self._emit_sequence(
            graph,
            ast,
            function_id,
            self._statements(finally_body),
            [(finally_entry, "finally-body")],
            exit_node,
            source,
            break_target,
            continue_target,
            terminal_target,
        )
        for tail, _ in finally_tails:
            graph.add_edge(
                tail,
                try_exit,
                kind="finally-complete",
                overlay="cfg",
            )
            if terminal_or_uncaught:
                graph.add_edge(
                    tail,
                    terminal_target or exit_node,
                    kind="finally-resume-terminal",
                    overlay="cfg",
                    fidelity="source-conservative",
                )
        return [(try_exit, "next")]

    def _emit_switch(
        self,
        graph: ProgramGraph,
        ast: FileAST,
        function_id: str,
        statement: Node,
        statement_id: str,
        exit_node: str,
        source: bytes,
        continue_target: str | None,
        terminal_target: str | None,
    ) -> list[tuple[str, str]]:
        switch_exit = f"{statement_id}::switch-exit"
        graph.add_node(
            switch_exit,
            kind="control-join",
            function=function_id,
            definitions=[],
            uses=[],
        )
        if statement.type == "when_expression":
            cases = [child for child in statement.named_children if child.type == "when_entry"]
        else:
            body = statement.child_by_field_name("body")
            cases = [
                child
                for child in (body.named_children if body is not None else [])
                if child.type in {"switch_block_statement_group", "switch_rule"}
            ]
        if not cases:
            graph.add_edge(
                statement_id,
                switch_exit,
                kind="no-match",
                overlay="cfg",
            )
            return [(switch_exit, "next")]

        entries: list[str] = []
        for index, case in enumerate(cases):
            entry = f"{statement_id}::case-entry:{index}"
            entries.append(entry)
            graph.add_node(
                entry,
                kind="control-join",
                function=function_id,
                definitions=[],
                uses=[],
            )
            case_text = self._text(case, source).lstrip()
            is_default = case_text.startswith(("default", "else"))
            graph.add_edge(
                statement_id,
                entry,
                kind="default" if is_default else "case",
                overlay="cfg",
            )

        for index, case in enumerate(cases):
            if statement.type == "when_expression":
                body = case.child_by_field_name("body")
                if body is None:
                    body = next(
                        (
                            child
                            for child in reversed(case.named_children)
                            if child.type not in {"when_condition", "number_literal"}
                        ),
                        None,
                    )
                case_statements = self._statements(body)
            else:
                case_statements = [
                    child for child in case.named_children if child.type != "switch_label"
                ]
            case_tails = self._emit_sequence(
                graph,
                ast,
                function_id,
                case_statements,
                [(entries[index], "case-body")],
                exit_node,
                source,
                switch_exit,
                continue_target,
                terminal_target,
            )
            if statement.type != "when_expression" and index + 1 < len(entries):
                for tail, _ in case_tails:
                    graph.add_edge(
                        tail,
                        entries[index + 1],
                        kind="fallthrough",
                        overlay="cfg",
                    )
            else:
                for tail, _ in case_tails:
                    graph.add_edge(
                        tail,
                        switch_exit,
                        kind="case-complete",
                        overlay="cfg",
                    )
        if not any(
            data.get("kind") == "default" for _, _, data in graph.out_edges(statement_id, data=True)
        ):
            graph.add_edge(
                statement_id,
                switch_exit,
                kind="no-match",
                overlay="cfg",
            )
        return [(switch_exit, "next")]

    def _build_data_overlays(
        self,
        graph: ProgramGraph,
        summary: ProgramGraphSummary,
    ) -> None:
        functions = [
            node for node, data in graph.nodes(data=True) if data.get("kind") == "function"
        ]
        for function in functions:
            members = {
                target
                for _, target, data in graph.out_edges(function, data=True)
                if data.get("kind") == "contains"
            }
            entries = [node for node in members if graph.nodes[node].get("kind") == "entry"]
            if not entries:
                continue
            nodes = {
                node
                for node, data in graph.nodes(data=True)
                if data.get("function") == function
                and data.get("kind") in {"control-join", "entry", "statement", "exit"}
            }
            predecessors: dict[str, set[str]] = defaultdict(set)
            for source, target, data in graph.edges(data=True):
                if source in nodes and target in nodes and data.get("overlay") == "cfg":
                    predecessors[target].add(source)

            in_defs: dict[str, dict[str, set[str]]] = {node: {} for node in nodes}
            out_defs: dict[str, dict[str, set[str]]] = {node: {} for node in nodes}
            for _ in range(max(len(nodes) * 2, 1)):
                changed = False
                for node in sorted(nodes):
                    merged: dict[str, set[str]] = defaultdict(set)
                    for predecessor in predecessors.get(node, set()):
                        for variable, definitions in out_defs[predecessor].items():
                            merged[variable].update(definitions)
                    current_in = {key: set(value) for key, value in merged.items()}
                    current_out = {key: set(value) for key, value in current_in.items()}
                    for variable in graph.nodes[node].get("definitions", []):
                        current_out[variable] = {node}
                    if current_in != in_defs[node] or current_out != out_defs[node]:
                        in_defs[node] = current_in
                        out_defs[node] = current_out
                        changed = True
                if not changed:
                    break
            else:
                summary.warnings.append(f"reaching definitions did not converge: {function}")

            state_for_definition: dict[tuple[str, str], str] = {}
            for node in nodes:
                for variable in graph.nodes[node].get("definitions", []):
                    state = f"{function}::data-state:{node}:{variable}"
                    state_for_definition[(node, variable)] = state
                    graph.add_node(
                        state,
                        kind="data-state",
                        function=function,
                        variable=variable,
                        producer_statement=node,
                    )
                    graph.add_edge(
                        node,
                        state,
                        kind="produces-state",
                        overlay="dtg",
                        variable=variable,
                    )

            for node in nodes:
                output_variables = graph.nodes[node].get("definitions", [])
                input_variables = graph.nodes[node].get("uses", [])
                for output_variable in output_variables:
                    output_state = state_for_definition.get((node, output_variable))
                    if output_state is None:
                        continue
                    for input_variable in input_variables:
                        for definition in in_defs[node].get(input_variable, set()):
                            input_state = state_for_definition.get((definition, input_variable))
                            if input_state is None:
                                continue
                            graph.add_edge(
                                input_state,
                                output_state,
                                kind="transforms",
                                overlay="dtg",
                                statement=node,
                                input_variable=input_variable,
                                output_variable=output_variable,
                            )

            for node in nodes:
                uses = graph.nodes[node].get("uses", [])
                for variable in uses:
                    reaching = in_defs[node].get(variable, set())
                    for definition in reaching:
                        graph.add_edge(
                            definition,
                            node,
                            kind="def-use",
                            overlay="dfg",
                            variable=variable,
                        )
                if len(predecessors.get(node, set())) >= 2:
                    for variable in uses:
                        reaching = in_defs[node].get(variable, set())
                        if len(reaching) < 2:
                            continue
                        phi = f"{function}::ssa:phi:{node}:{variable}"
                        graph.add_node(
                            phi,
                            kind="ssa-phi",
                            function=function,
                            variable=variable,
                            definitions=[variable],
                            uses=[variable],
                        )
                        for definition in reaching:
                            graph.add_edge(
                                definition,
                                phi,
                                kind="phi-input",
                                overlay="ssa",
                                variable=variable,
                            )
                        graph.add_edge(
                            phi,
                            node,
                            kind="def-use",
                            overlay="dfg",
                            variable=variable,
                        )

                allocations: dict[str, str] = graph.nodes[node].get("allocations", {})
                for variable, allocated_type in allocations.items():
                    allocation = f"{node}::allocation:{variable}"
                    graph.add_node(
                        allocation,
                        kind="allocation",
                        function=function,
                        allocated_type=allocated_type,
                        variable=variable,
                    )
                    graph.add_edge(
                        node,
                        allocation,
                        kind="points-to",
                        overlay="points-to",
                        variable=variable,
                    )
                aliases: dict[str, str] = graph.nodes[node].get("aliases", {})
                for target_variable, source_variable in aliases.items():
                    for definition in in_defs[node].get(source_variable, set()):
                        graph.add_edge(
                            definition,
                            node,
                            kind="alias",
                            overlay="points-to",
                            source_variable=source_variable,
                            target_variable=target_variable,
                        )

    def _data_facts(self, text: str) -> dict[str, Any]:
        scrubbed = re.sub(r"(['\"])(?:\\.|(?!\1).)*\1", "", text, flags=re.DOTALL)
        definitions: set[str] = set()
        for match in self._DECLARATION.finditer(scrubbed):
            definitions.add(match.group(1) or match.group(2))
        java_declaration = self._JAVA_DECLARATION.search(scrubbed)
        if java_declaration:
            definitions.add(java_declaration.group(1))
        definitions.update(self._ASSIGNMENT.findall(scrubbed))
        identifiers = set(self._IDENTIFIER.findall(scrubbed))
        uses = sorted(
            identifier
            for identifier in identifiers - definitions - self._KEYWORDS
            if not identifier[0].isupper()
        )
        allocations: dict[str, str] = {}
        kotlin = self._KOTLIN_ALLOCATION.search(scrubbed)
        if kotlin:
            allocations[kotlin.group(1)] = kotlin.group(2)
        java = self._JAVA_ALLOCATION.search(scrubbed)
        if java and definitions:
            allocations[sorted(definitions)[0]] = java.group(1)
        aliases: dict[str, str] = {}
        alias = self._ALIAS.search(scrubbed.strip())
        if alias and alias.group(1) != alias.group(2):
            aliases[alias.group(1)] = alias.group(2)
        return {
            "definitions": sorted(definitions),
            "uses": uses,
            "allocations": allocations,
            "aliases": aliases,
        }

    def _statements(self, node: Node | None) -> list[Node]:
        if node is None:
            return []
        if node.type in self._BLOCK_TYPES:
            children = list(node.named_children)
            if len(children) == 1 and children[0].type in self._BLOCK_TYPES:
                return self._statements(children[0])
            return children
        return [node]

    @staticmethod
    def _statement_id(function_id: str, node: Node) -> str:
        return f"{function_id}::cfg:{node.start_byte}:{node.type}"

    @staticmethod
    def _text(node: Node | None, source: bytes) -> str:
        if node is None:
            return ""
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
