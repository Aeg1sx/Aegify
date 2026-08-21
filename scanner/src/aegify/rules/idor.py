"""IDOR and Authorization detection rules."""

from __future__ import annotations

import re
from typing import Any

from aegify.graph_types import CodeGraph
from aegify.models import (
    FileAST,
    Finding,
    Language,
    Severity,
    TaintFlow,
)
from aegify.rules.base import RuleDefinition, SecurityRule, register_rule

# Patterns indicating ownership/authorization checks
OWNERSHIP_PATTERNS = [
    r"current_user",
    r"request\.user",
    r"session\[.user.\]",
    r"get_current_user",
    r"user_id\s*==",
    r"owner_id\s*==",
    r"belongs_to",
    r"has_permission",
    r"check_access",
    r"authorize",
    r"can_access",
]

AUTH_DECORATORS = [
    "auth_required",
    "login_required",
    "permission_required",
    "jwt_required",
    "authenticate",
    "requires_auth",
    "Authorize",
    "PreAuthorize",
]

# DB query patterns that take an ID parameter
DB_QUERY_PATTERNS = [
    r"\.get$",
    r"\.find$",
    r"\.filter$",
    r"\.find_by_id$",
    r"\.findById$",
    r"\.findOne$",
    r"\.query$",
    r"\.execute$",
    r"get_object_or_404",
    r"get$",
    r"filter$",
    r"findById$",
    r"findOne$",
]


class IDORRule(SecurityRule):
    """Detect Insecure Direct Object Reference (IDOR) patterns."""

    definition = RuleDefinition(
        id="AEG-IDOR-001",
        name="Insecure Direct Object Reference (IDOR)",
        description=(
            "A user-supplied ID is used to fetch a database object without verifying "
            "that the current user owns or has access to that object. This can allow "
            "unauthorized access to other users' data."
        ),
        severity=Severity.HIGH,
        default_confidence=0.75,
        languages=[Language.PYTHON, Language.JAVASCRIPT, Language.JAVA, Language.GO],
        cwe_id=639,
        owasp_category="A01:2021-Broken Access Control",
        requires_taint_path=False,
        defense_patterns=["current_user", "owner", "permission", "authorize", "access_control"],
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "ast_pattern_analysis",
            "patterns": {
                "entry_point_decorators": [
                    "route",
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "Mapping",
                    "api_view",
                    "HandleFunc",
                ],
                "db_query_patterns": [p.lstrip(r"\.").rstrip("$") for p in DB_QUERY_PATTERNS],
                "id_argument_pattern": r"(id|_id|pk|uuid|slug)",
                "ownership_check_patterns": OWNERSHIP_PATTERNS,
                "auth_decorators": AUTH_DECORATORS,
            },
            "call_graph_analysis": True,
            "logic": (
                "1. Find route handler functions (by decorator)\n"
                "2. Check if function contains DB queries with user-supplied ID parameters\n"
                "3. Check if ownership/authorization verification exists in the function\n"
                "4. Check decorators and call graph callers for auth decorators\n"
                "5. Report if DB query with ID found but no ownership check present"
            ),
            "confidence_adjustment": (
                "Base: 0.75. Reduced to 0.45 (x0.6) if auth decorator is present "
                "but no ownership check (auth != authorization)."
            ),
        }

    def evaluate(
        self,
        file_asts: list[FileAST],
        call_graph: CodeGraph,
        taint_flows: list[TaintFlow],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for ast in file_asts:
            if ast.language not in self.definition.languages:
                continue

            for func in ast.functions:
                # Check if this function is an entry point (route handler)
                is_endpoint = any(
                    any(
                        ep in dec
                        for ep in (
                            "route",
                            "get",
                            "post",
                            "put",
                            "delete",
                            "patch",
                            "Mapping",
                            "api_view",
                            "HandleFunc",
                        )
                    )
                    for dec in func.decorators
                )
                if not is_endpoint:
                    continue

                # Find calls within this function that look like DB queries with an ID
                has_db_query_with_id = False
                has_ownership_check = False
                db_call_line = 0

                for call in ast.calls:
                    if call.in_function != func.name:
                        continue

                    call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee

                    # Check for DB query with ID parameter
                    for pattern in DB_QUERY_PATTERNS:
                        if re.search(pattern, call_text, re.IGNORECASE):
                            # Check if arguments contain user-supplied ID patterns
                            args_text = " ".join(call.arguments)
                            if re.search(r"(id|_id|pk|uuid|slug)", args_text, re.IGNORECASE):
                                has_db_query_with_id = True
                                db_call_line = call.line
                            break

                    # Check for ownership/authorization patterns
                    for pattern in OWNERSHIP_PATTERNS:
                        if re.search(pattern, call_text, re.IGNORECASE):
                            has_ownership_check = True
                            break
                    args_text = " ".join(call.arguments)
                    for pattern in OWNERSHIP_PATTERNS:
                        if re.search(pattern, args_text, re.IGNORECASE):
                            has_ownership_check = True
                            break

                # Check decorators for auth
                has_auth_decorator = any(
                    any(auth in dec for auth in AUTH_DECORATORS) for dec in func.decorators
                )

                # Also check call graph: do callers have auth?
                function_id = func.symbol_id or func.qualified_name
                if not has_auth_decorator and function_id in call_graph:
                    for caller in call_graph.predecessors(function_id):
                        caller_data = call_graph.nodes.get(caller, {}).get("data")
                        if caller_data and caller_data.decorators:
                            if any(
                                any(auth in dec for auth in AUTH_DECORATORS)
                                for dec in caller_data.decorators
                            ):
                                has_auth_decorator = True
                                break

                if has_db_query_with_id and not has_ownership_check:
                    confidence = 0.75
                    if has_auth_decorator:
                        confidence *= 0.6  # Auth present but no ownership check
                    findings.append(
                        self._create_finding(
                            file_path=ast.file_path,
                            line_start=db_call_line or func.line_start,
                            line_end=db_call_line or func.line_end,
                            code_snippet="",
                            message=(
                                f"Potential IDOR in '{func.name}': database query uses a "
                                f"user-supplied ID without ownership verification. "
                                f"Ensure the current user has access to the requested resource."
                            ),
                            confidence=confidence,
                        )
                    )

        return findings


class MassAssignmentRule(SecurityRule):
    """Detect mass assignment from request body to model."""

    definition = RuleDefinition(
        id="AEG-IDOR-002",
        name="Mass Assignment",
        description=(
            "Request body data is directly passed to a model creation/update method "
            "without filtering allowed fields. Attackers may set unauthorized fields "
            "like 'is_admin' or 'role'."
        ),
        severity=Severity.HIGH,
        default_confidence=0.7,
        languages=[Language.PYTHON, Language.JAVASCRIPT, Language.JAVA],
        cwe_id=915,
        owasp_category="A01:2021-Broken Access Control",
        requires_taint_path=False,
        defense_patterns=["schema", "serializer", "whitelist", "allowlist", "pick"],
    )

    MASS_ASSIGN_PATTERNS = [
        (r"\.create$", r"(request\.(json|data|body)|req\.body|\*\*request)"),
        (r"\.update$", r"(request\.(json|data|body)|req\.body|\*\*request)"),
        (r"create$", r"(request\.(json|data|body)|req\.body|\*\*request)"),
        (r"update$", r"(request\.(json|data|body)|req\.body|\*\*request)"),
        (r"\.save$", r"(request\.(json|data|body)|req\.body)"),
    ]

    SAFE_PATTERNS = [
        r"serializer",
        r"schema",
        r"validate",
        r"\.only\(",
        r"\.pick\(",
        r"\.permit\(",
        r"allowed_fields",
        r"whitelist",
        r"allowlist",
    ]

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "pattern_matching",
            "patterns": {
                "method_patterns": [
                    {"callee": p[0], "args": p[1]} for p in self.MASS_ASSIGN_PATTERNS
                ],
                "safe_patterns": self.SAFE_PATTERNS,
            },
            "logic": (
                "1. Match function calls to DB creation/update methods (create, update, save)\n"
                "2. Check if arguments contain direct request body data "
                "(request.json, req.body, **request)\n"
                "3. Verify no safe pattern is present (serializer, schema, validate, allowlist)\n"
                "4. Report if request body data flows directly to model without field filtering"
            ),
        }

    def evaluate(
        self,
        file_asts: list[FileAST],
        call_graph: CodeGraph,
        taint_flows: list[TaintFlow],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for ast in file_asts:
            if ast.language not in self.definition.languages:
                continue

            for call in ast.calls:
                call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
                args_text = " ".join(call.arguments)

                for method_pattern, arg_pattern in self.MASS_ASSIGN_PATTERNS:
                    if not re.search(method_pattern, call_text, re.IGNORECASE):
                        continue
                    if not re.search(arg_pattern, args_text, re.IGNORECASE):
                        continue

                    # Check if there's a safe pattern nearby
                    is_safe = any(
                        re.search(safe, args_text, re.IGNORECASE) for safe in self.SAFE_PATTERNS
                    )
                    if is_safe:
                        continue

                    findings.append(
                        self._create_finding(
                            file_path=ast.file_path,
                            line_start=call.line,
                            line_end=call.line,
                            code_snippet="",
                            message=(
                                f"Potential mass assignment at line {call.line}: "
                                f"request data passed directly to '{call_text}' "
                                f"without field filtering. Use a schema or allowlist."
                            ),
                        )
                    )
                    break

        return findings


class InsecureDirectReferenceRule(SecurityRule):
    """Detect file/resource access with user input and no access control."""

    definition = RuleDefinition(
        id="AEG-IDOR-003",
        name="Insecure Direct File Reference",
        description=(
            "User-controlled input is used to access files or resources without "
            "proper access control validation."
        ),
        severity=Severity.HIGH,
        default_confidence=0.8,
        languages=[
            Language.PYTHON,
            Language.JAVASCRIPT,
            Language.JAVA,
            Language.GO,
            Language.RUST,
        ],
        cwe_id=22,
        owasp_category="A01:2021-Broken Access Control",
        requires_taint_path=True,
        defense_patterns=["validate_path", "sanitize", "realpath", "abspath"],
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "taint_analysis",
            "taint": {
                "sink_types": ["file_access"],
                "source_types": ["user_input", "request_param", "query_string"],
                "sanitizers": self.definition.defense_patterns,
            },
            "additional_checks": {
                "path_validation_patterns": [
                    "realpath",
                    "abspath",
                    "resolve",
                    "normalize",
                    "validate",
                ],
                "logic": (
                    "After finding taint flow to file_access sink, checks all "
                    "propagation steps for path validation function calls. "
                    "Only reports if NO path validation is found in the entire flow."
                ),
            },
        }

    def evaluate(
        self,
        file_asts: list[FileAST],
        call_graph: CodeGraph,
        taint_flows: list[TaintFlow],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for flow in taint_flows:
            if flow.sink.sink_type != "file_access":
                continue
            if flow.sanitized:
                continue

            # Check for path validation in the flow
            has_path_check = False
            for prop in flow.path:
                prop_text = prop.variable.lower()
                if any(
                    safe in prop_text
                    for safe in ("realpath", "abspath", "resolve", "normalize", "validate")
                ):
                    has_path_check = True
                    break

            if has_path_check:
                continue

            findings.append(
                self._create_finding(
                    file_path=flow.sink.file_path,
                    line_start=flow.sink.line,
                    line_end=flow.sink.line,
                    code_snippet="",
                    message=(
                        f"Insecure file access: user input from "
                        f"'{flow.source.variable}' (line {flow.source.line}) "
                        f"flows to file operation '{flow.sink.function}' "
                        f"(line {flow.sink.line}) without path validation."
                    ),
                    taint_flow=flow,
                )
            )

        return findings


# Register rules
register_rule(IDORRule())
register_rule(MassAssignmentRule())
register_rule(InsecureDirectReferenceRule())
