"""JVM build discovery and source-level CHA/RTA fallback analysis."""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from codeguard.models import (
    CallSite,
    ClassDef,
    FileAST,
    FunctionDef,
    JvmBuildProject,
    Language,
    SemanticRelationship,
)
from codeguard.scanner.workspace import WorkspaceRepository
from codeguard.semantic.signatures import jvm_overload_score


@dataclass
class JvmAnalysis:
    """Normalized JVM graph facts and their precision counters."""

    types: set[str] = field(default_factory=set)
    relationships: list[SemanticRelationship] = field(default_factory=list)
    build_projects: list[JvmBuildProject] = field(default_factory=list)
    cha_edges: int = 0
    rta_edges: int = 0
    points_to_contexts: int = 0
    points_to_iterations: int = 0
    points_to_allocations: int = 0
    points_to_edges: int = 0
    points_to_alias_edges: int = 0
    points_to_argument_edges: int = 0
    points_to_return_edges: int = 0
    points_to_receiver_calls: int = 0
    points_to_direct_calls: int = 0
    points_to_truncated: bool = False
    warnings: list[str] = field(default_factory=list)


_CallString = tuple[str, ...]
_VarKey = tuple[str, _CallString, str]


@dataclass(frozen=True)
class _AllocationTemplate:
    variable: str
    type_name: str
    line: int
    site: int


@dataclass
class _PointsFunction:
    node_id: str
    definition: FunctionDef
    ast: FileAST
    allocations: list[_AllocationTemplate] = field(default_factory=list)
    aliases: list[tuple[str, str, int]] = field(default_factory=list)
    return_variables: set[str] = field(default_factory=set)
    calls: list[CallSite] = field(default_factory=list)
    call_results: dict[tuple[int, int, str], str] = field(default_factory=dict)


@dataclass(frozen=True)
class _AllocationFact:
    node_id: str
    type_id: str
    type_name: str
    function_id: str
    context: _CallString
    variable: str
    file_path: str
    repository_id: str
    line: int


@dataclass
class JvmModuleAnalysis:
    """Build-descriptor module membership and dependency facts."""

    modules: set[str] = field(default_factory=set)
    relationships: list[SemanticRelationship] = field(default_factory=list)
    dependency_edges: int = 0
    warnings: list[str] = field(default_factory=list)


class JvmBuildDiscoverer:
    """Discover nested Maven/Gradle module boundaries without running builds."""

    _GRADLE_INCLUDE = re.compile(r"\binclude\s*\((?P<body>[^)]*)\)")
    _QUOTED = re.compile(r"['\"]([^'\"]+)['\"]")

    def discover(self, repository: WorkspaceRepository) -> list[JvmBuildProject]:
        root = repository.path
        descriptors = sorted(
            set(root.rglob("pom.xml"))
            | set(root.rglob("settings.gradle"))
            | set(root.rglob("settings.gradle.kts"))
            | set(root.rglob("build.gradle"))
            | set(root.rglob("build.gradle.kts"))
        )
        gradle_roots = sorted(
            {
                path.parent
                for path in descriptors
                if path.name in {"settings.gradle", "settings.gradle.kts"}
            },
            key=lambda path: len(path.parts),
        )
        build_roots: dict[tuple[Path, str], set[Path]] = defaultdict(set)
        for descriptor in descriptors:
            name = descriptor.name
            system = "maven" if name == "pom.xml" else "gradle"
            project_root = descriptor.parent
            if system == "gradle":
                enclosing = [
                    candidate for candidate in gradle_roots if descriptor.is_relative_to(candidate)
                ]
                if enclosing:
                    project_root = max(enclosing, key=lambda path: len(path.parts))
            build_roots[(project_root, system)].add(descriptor)

        projects: list[JvmBuildProject] = []
        for (project_root, system), files in sorted(
            build_roots.items(), key=lambda item: str(item[0][0])
        ):
            modules = self._modules(project_root, system, files)
            source_roots = self._source_roots(project_root, modules)
            projects.append(
                JvmBuildProject(
                    repository_id=repository.id,
                    root=str(project_root),
                    build_system=system,
                    descriptors=[str(path) for path in sorted(files)],
                    modules=modules,
                    source_roots=source_roots,
                )
            )
        return projects

    def _modules(self, root: Path, system: str, files: set[Path]) -> list[str]:
        modules: set[str] = set()
        if system == "gradle":
            settings = [
                path for path in files if path.name in {"settings.gradle", "settings.gradle.kts"}
            ]
            for path in settings:
                try:
                    text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    continue
                for match in self._GRADLE_INCLUDE.finditer(text):
                    modules.update(self._QUOTED.findall(match.group("body")))
        else:
            pom = root / "pom.xml"
            if pom.is_file():
                try:
                    tree = ET.parse(pom)
                except (OSError, ET.ParseError):
                    tree = None
                if tree is not None:
                    for element in tree.getroot().iter():
                        if element.tag.rsplit("}", 1)[-1] == "module" and element.text:
                            modules.add(element.text.strip())
        return sorted(module for module in modules if module)

    @staticmethod
    def _source_roots(root: Path, modules: list[str]) -> list[str]:
        candidates: set[Path] = set()
        module_roots = [root]
        module_roots.extend(root / module.replace(":", "/") for module in modules)
        for module_root in module_roots:
            for relative in (
                "src/main/java",
                "src/main/kotlin",
                "src/test/java",
                "src/test/kotlin",
            ):
                candidate = module_root / relative
                if candidate.is_dir():
                    candidates.add(candidate)
        return [str(path) for path in sorted(candidates)]


class JvmModuleGraphAnalyzer:
    """Recover coarse, explicitly labeled reachability between JVM modules."""

    _GRADLE_PROJECT = re.compile(
        r"\b(?:api|compileOnly|implementation|runtimeOnly|testImplementation)\s*"
        r"\(?\s*project\s*\(\s*['\"]:(?P<module>[^'\"]+)['\"]\s*\)"
    )

    def analyze(
        self,
        repository: WorkspaceRepository,
        file_asts: list[FileAST],
        projects: list[JvmBuildProject],
    ) -> JvmModuleAnalysis:
        result = JvmModuleAnalysis()
        repository_asts = [ast for ast in file_asts if ast.repository_id == repository.id]
        for project in projects:
            root = Path(project.root).resolve()
            module_names = {self._module_name(module) for module in project.modules}
            module_names.add("root")
            for module in sorted(module_names):
                result.modules.add(
                    self._module_id(
                        repository.id,
                        self._root_key(repository.path, root),
                        module,
                    )
                )
            self._add_memberships(
                result,
                repository,
                repository_asts,
                root,
                module_names,
            )
            if project.build_system == "gradle":
                self._add_gradle_dependencies(result, repository, root, module_names)
            else:
                self._add_maven_dependencies(result, repository, root, module_names)
        return result

    def _add_memberships(
        self,
        result: JvmModuleAnalysis,
        repository: WorkspaceRepository,
        file_asts: list[FileAST],
        root: Path,
        module_names: set[str],
    ) -> None:
        for ast in file_asts:
            source = Path(ast.file_path).resolve()
            try:
                relative = source.relative_to(root)
            except ValueError:
                continue
            module = self._module_for_path(relative, module_names)
            module_id = self._module_id(
                repository.id,
                self._root_key(repository.path, root),
                module,
            )
            file_id = f"repo:{repository.id}:file:{ast.module_path}"
            result.relationships.extend(
                [
                    SemanticRelationship(
                        source=file_id,
                        target=module_id,
                        kind="member-of-module",
                        repository_id=repository.id,
                        file_path=ast.module_path,
                        confidence=0.98,
                        provider="codeguard-jvm-build",
                        fidelity="build-descriptor",
                    ),
                    SemanticRelationship(
                        source=module_id,
                        target=file_id,
                        kind="contains-file",
                        repository_id=repository.id,
                        file_path=ast.module_path,
                        confidence=0.98,
                        provider="codeguard-jvm-build",
                        fidelity="build-descriptor",
                    ),
                ]
            )

    def _add_gradle_dependencies(
        self,
        result: JvmModuleAnalysis,
        repository: WorkspaceRepository,
        root: Path,
        modules: set[str],
    ) -> None:
        for module in sorted(modules):
            module_root = root if module == "root" else root / module
            text = self._read_descriptors(
                module_root / "build.gradle",
                module_root / "build.gradle.kts",
            )
            for match in self._GRADLE_PROJECT.finditer(text):
                target = self._module_name(match.group("module"))
                if target not in modules:
                    continue
                self._add_dependency(result, repository, root, module, target)

    def _add_maven_dependencies(
        self,
        result: JvmModuleAnalysis,
        repository: WorkspaceRepository,
        root: Path,
        modules: set[str],
    ) -> None:
        artifact_to_module: dict[str, str] = {}
        poms: dict[str, ET.Element] = {}
        for module in sorted(modules):
            pom = root / "pom.xml" if module == "root" else root / module / "pom.xml"
            if not pom.is_file():
                continue
            try:
                document = ET.parse(pom).getroot()
            except (OSError, ET.ParseError) as error:
                result.warnings.append(f"{pom}: {error}")
                continue
            poms[module] = document
            artifact = next(
                (
                    element.text.strip()
                    for element in document
                    if element.tag.rsplit("}", 1)[-1] == "artifactId" and element.text
                ),
                "",
            )
            if artifact:
                artifact_to_module[artifact] = module
        for module, document in poms.items():
            for dependency in document.iter():
                if dependency.tag.rsplit("}", 1)[-1] != "dependency":
                    continue
                artifact = next(
                    (
                        child.text.strip()
                        for child in dependency
                        if child.tag.rsplit("}", 1)[-1] == "artifactId" and child.text
                    ),
                    "",
                )
                target = artifact_to_module.get(artifact)
                if target and target != module:
                    self._add_dependency(result, repository, root, module, target)

    def _add_dependency(
        self,
        result: JvmModuleAnalysis,
        repository: WorkspaceRepository,
        root: Path,
        source: str,
        target: str,
    ) -> None:
        relationship = SemanticRelationship(
            source=self._module_id(
                repository.id,
                self._root_key(repository.path, root),
                source,
            ),
            target=self._module_id(
                repository.id,
                self._root_key(repository.path, root),
                target,
            ),
            kind="module-dependency",
            repository_id=repository.id,
            file_path=str(root),
            confidence=0.72,
            provider="codeguard-jvm-build",
            fidelity="declared-module-dependency-coarse",
        )
        if relationship not in result.relationships:
            result.relationships.append(relationship)
            result.dependency_edges += 1

    @staticmethod
    def _read_descriptors(*paths: Path) -> str:
        snippets: list[str] = []
        for path in paths:
            if not path.is_file():
                continue
            try:
                snippets.append(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError):
                continue
        return "\n".join(snippets)

    @staticmethod
    def _module_name(module: str) -> str:
        return module.strip(":").replace(":", "/") or "root"

    @staticmethod
    def _module_for_path(path: Path, modules: set[str]) -> str:
        candidates = [
            module
            for module in modules
            if module != "root" and path.parts[: len(Path(module).parts)] == Path(module).parts
        ]
        return max(candidates, key=lambda item: len(Path(item).parts)) if candidates else "root"

    @staticmethod
    def _root_key(repository_root: Path, build_root: Path) -> str:
        relative = build_root.resolve().relative_to(repository_root.resolve())
        return relative.as_posix() if relative.parts else "root"

    @staticmethod
    def _module_id(repository_id: str, root_key: str, module: str) -> str:
        return f"repo:{repository_id}:jvm-module:{root_key}:{module}"


class JvmSemanticAnalyzer:
    """Build source-derived type hierarchy and conservative dispatch edges."""

    _JAVA_BINDING = re.compile(
        r"\b(?P<declared>[A-Z][\w.$]*(?:\s*<[^;=]+>)?)\s+"
        r"(?P<variable>[a-zA-Z_$][\w$]*)\s*=\s*new\s+"
        r"(?P<runtime>[A-Z][\w.$]*)\s*\("
    )
    _KOTLIN_BINDING = re.compile(
        r"\b(?:val|var)\s+(?P<variable>[a-zA-Z_$][\w$]*)\s*:\s*"
        r"(?P<declared>[A-Z][\w.$<>?]*)\s*=\s*"
        r"(?P<runtime>[A-Z][\w.$]*)\s*\("
    )
    _JAVA_NEW = re.compile(r"\bnew\s+(?P<runtime>[A-Z][\w.$]*)\s*\(")
    _KOTLIN_INFERRED_BINDING = re.compile(
        r"\b(?:val|var)\s+(?P<variable>[a-zA-Z_$][\w$]*)\s*=\s*"
        r"(?P<runtime>[A-Z][\w.$]*)\s*\("
    )
    _ALIAS_BINDING = re.compile(
        r"(?:\b(?:val|var|final)\s+|\b[A-Z][\w.$<>?,\[\]]*\s+)?"
        r"(?P<target>[a-zA-Z_$][\w$]*)\s*=\s*"
        r"(?P<source>[a-zA-Z_$][\w$]*)\s*(?:;|$)",
        re.MULTILINE,
    )
    _RETURN_VARIABLE = re.compile(
        r"\breturn\s+(?P<variable>[a-zA-Z_$][\w$]*)\s*(?:;|$)",
        re.MULTILINE,
    )
    _RETURN_JAVA_ALLOCATION = re.compile(r"\breturn\s+new\s+(?P<runtime>[A-Z][\w.$]*)\s*\(")
    _RETURN_KOTLIN_ALLOCATION = re.compile(r"\breturn\s+(?P<runtime>[A-Z][\w.$]*)\s*\(")
    _PACKAGE = re.compile(r"^\s*package\s+(?P<package>[A-Za-z_$][\w.$]*)", re.MULTILINE)
    _RETURN_VALUE = "<return>"

    def __init__(
        self,
        *,
        points_to_context_depth: int = 2,
        max_points_to_contexts: int = 10_000,
        max_points_to_iterations: int = 64,
    ) -> None:
        if points_to_context_depth < 1 or points_to_context_depth > 4:
            raise ValueError("points_to_context_depth must be between 1 and 4")
        if max_points_to_contexts < 1:
            raise ValueError("max_points_to_contexts must be positive")
        if max_points_to_iterations < 1:
            raise ValueError("max_points_to_iterations must be positive")
        self.points_to_context_depth = points_to_context_depth
        self.max_points_to_contexts = max_points_to_contexts
        self.max_points_to_iterations = max_points_to_iterations

    def analyze(self, file_asts: list[FileAST]) -> JvmAnalysis:
        result = JvmAnalysis()
        jvm_asts = [ast for ast in file_asts if ast.language in {Language.JAVA, Language.KOTLIN}]
        type_candidates: dict[tuple[str, str], list[str]] = defaultdict(list)
        qualified_types: dict[str, list[str]] = defaultdict(list)
        class_by_id: dict[str, tuple[FileAST, ClassDef]] = {}
        methods: dict[tuple[str, str], list[FunctionDef]] = defaultdict(list)
        parents: dict[str, set[str]] = defaultdict(set)

        for ast in jvm_asts:
            for cls in ast.classes:
                type_id = self._type_id(ast, cls.name)
                type_candidates[(ast.repository_id, self._simple_type(cls.name))].append(type_id)
                qualified_types[self._qualified_type_name(ast, cls.name)].append(type_id)
                class_by_id[type_id] = (ast, cls)
                result.types.add(type_id)
                for method in cls.methods:
                    methods[(type_id, method.name)].append(method)

        for type_id, (ast, cls_obj) in class_by_id.items():
            for raw_base in cls_obj.base_classes:
                base = self._simple_type(str(raw_base))
                parent_id = self._resolve_type(
                    type_candidates,
                    class_by_id,
                    ast,
                    base,
                    qualified_types,
                )
                if parent_id is None:
                    matches = [
                        candidate
                        for (repo, name), candidates in type_candidates.items()
                        if name == base and repo != ast.repository_id
                        for candidate in candidates
                    ]
                    if len(matches) == 1:
                        parent_id = matches[0]
                if parent_id is None:
                    continue
                parents[type_id].add(parent_id)
                result.relationships.append(
                    self._relationship(type_id, parent_id, "inherits", ast, 0.92)
                )
                for method in cls_obj.methods:
                    parent_methods = [
                        candidate
                        for candidate in methods.get((parent_id, method.name), [])
                        if candidate.callable_descriptor == method.callable_descriptor
                    ]
                    if len(parent_methods) == 1:
                        parent_method = parent_methods[0]
                        child_method = method.symbol_id or method.callable_name
                        result.relationships.append(
                            self._relationship(
                                child_method,
                                parent_method.symbol_id or parent_method.callable_name,
                                "overrides",
                                ast,
                                0.90,
                            )
                        )

        for ast in jvm_asts:
            bindings, _ = self._bindings(ast)
            for call in ast.calls:
                if not call.receiver or call.receiver[0].isupper():
                    continue
                declared = call.receiver_type
                if not declared and call.receiver in bindings:
                    declared = bindings[call.receiver][0]
                if not declared:
                    continue
                declared_id = self._resolve_type(
                    type_candidates,
                    class_by_id,
                    ast,
                    self._simple_type(declared),
                    qualified_types,
                )
                if declared_id is None:
                    continue
                caller = call.caller_symbol_id or self._caller_symbol(ast, call.in_function)
                if caller is None:
                    continue
                cha_targets = self._dispatch_targets(
                    declared_id, call, class_by_id, methods, parents
                )
                for target in cha_targets:
                    result.relationships.append(
                        self._relationship(caller, target, "cha-call", ast, 0.76, call.line)
                    )
                    result.cha_edges += 1

        self._analyze_points_to(
            result,
            jvm_asts,
            type_candidates,
            qualified_types,
            class_by_id,
            methods,
            parents,
        )

        return result

    def _analyze_points_to(
        self,
        result: JvmAnalysis,
        jvm_asts: list[FileAST],
        type_candidates: dict[tuple[str, str], list[str]],
        qualified_types: dict[str, list[str]],
        class_by_id: dict[str, tuple[FileAST, ClassDef]],
        methods: dict[tuple[str, str], list[FunctionDef]],
        parents: dict[str, set[str]],
    ) -> None:
        """Solve bounded call-string-sensitive source points-to constraints.

        This is a monotone inclusion solver over allocation sites, local aliases,
        arguments, receivers, and returns.  It deliberately emits separate
        fidelity from compiler-index and bytecode facts.  Unknown field/reflection
        behavior stays unresolved instead of inventing a receiver target.
        """
        functions = self._points_functions(jvm_asts)
        if not functions:
            return
        functions_by_name: dict[str, list[str]] = defaultdict(list)
        functions_by_file: dict[tuple[str, str], list[str]] = defaultdict(list)
        type_for_function: dict[str, str] = {}
        for function_id, context in functions.items():
            functions_by_name[context.definition.name].append(function_id)
            functions_by_file[(context.definition.file_path, context.definition.name)].append(
                function_id
            )
            if context.definition.class_name:
                type_id = self._resolve_type(
                    type_candidates,
                    class_by_id,
                    context.ast,
                    self._simple_type(context.definition.class_name),
                    qualified_types,
                )
                if type_id is not None:
                    type_for_function[function_id] = type_id

        parameter_points: dict[_VarKey, set[str]] = defaultdict(set)
        return_points: dict[tuple[str, _CallString], set[str]] = defaultdict(set)
        observed_points: dict[_VarKey, set[str]] = defaultdict(set)
        allocation_facts: dict[str, _AllocationFact] = {}
        active_contexts: set[tuple[str, _CallString]] = {
            (function_id, ()) for function_id in functions
        }
        alias_events: set[tuple[_VarKey, _VarKey, int]] = set()
        argument_events: set[tuple[_VarKey, _VarKey, int, int]] = set()
        return_events: set[tuple[str, _CallString, _VarKey, int, int]] = set()
        rta_events: set[tuple[str, str, str, int]] = set()
        direct_events: set[tuple[str, str, str, int]] = set()
        truncated = False

        for iteration in range(1, self.max_points_to_iterations + 1):
            changed = False
            for function_id, call_string in sorted(list(active_contexts)):
                context = functions[function_id]
                local_points: dict[str, set[str]] = defaultdict(set)
                for parameter in context.definition.parameters:
                    local_points[parameter].update(
                        parameter_points.get((function_id, call_string, parameter), set())
                    )
                local_points["this"].update(
                    parameter_points.get((function_id, call_string, "this"), set())
                )
                local_points["self"].update(local_points["this"])

                for template in context.allocations:
                    type_id = self._resolve_type(
                        type_candidates,
                        class_by_id,
                        context.ast,
                        self._simple_type(template.type_name),
                        qualified_types,
                    )
                    if type_id is None:
                        continue
                    allocation = self._allocation_fact(
                        context,
                        call_string,
                        template,
                        type_id,
                    )
                    allocation_facts.setdefault(allocation.node_id, allocation)
                    local_points[template.variable].add(allocation.node_id)

                self._apply_alias_constraints(
                    context,
                    call_string,
                    local_points,
                    alias_events,
                )

                for call in context.calls:
                    targets, receiver_precise, direct_precise = self._points_call_targets(
                        call,
                        context,
                        local_points,
                        allocation_facts,
                        functions,
                        functions_by_name,
                        functions_by_file,
                        type_for_function,
                        type_candidates,
                        qualified_types,
                        class_by_id,
                        methods,
                        parents,
                    )
                    if not targets:
                        continue
                    if receiver_precise:
                        for target in targets:
                            rta_events.add(
                                (function_id, target, context.ast.module_path, call.line)
                            )
                    elif direct_precise:
                        for target in targets:
                            direct_events.add(
                                (function_id, target, context.ast.module_path, call.line)
                            )

                    target_call_string = self._next_points_context(
                        call_string,
                        context,
                        call,
                    )
                    argument_values = [
                        self._points_for_expression(
                            argument,
                            context,
                            call_string,
                            local_points,
                            allocation_facts,
                            type_candidates,
                            qualified_types,
                            class_by_id,
                            call.line,
                            index,
                        )
                        for index, argument in enumerate(call.arguments)
                    ]
                    receiver_values = set(local_points.get(call.receiver or "", set()))
                    result_variable = context.call_results.get(
                        (call.line, call.column, call.callee)
                    )

                    for target in sorted(targets):
                        target_context = functions.get(target)
                        if target_context is None:
                            continue
                        target_key = (target, target_call_string)
                        if target_key not in active_contexts:
                            if len(active_contexts) >= self.max_points_to_contexts:
                                truncated = True
                                continue
                            active_contexts.add(target_key)
                            changed = True
                        for index, parameter in enumerate(target_context.definition.parameters):
                            if index >= len(argument_values):
                                break
                            values = argument_values[index]
                            destination = (target, target_call_string, parameter)
                            before = len(parameter_points[destination])
                            parameter_points[destination].update(values)
                            if len(parameter_points[destination]) != before:
                                changed = True
                            source_variable = self._simple_expression_variable(
                                call.arguments[index]
                            )
                            if source_variable and values:
                                argument_events.add(
                                    (
                                        (function_id, call_string, source_variable),
                                        destination,
                                        call.line,
                                        call.column,
                                    )
                                )
                        if call.receiver and receiver_values:
                            destination = (target, target_call_string, "this")
                            before = len(parameter_points[destination])
                            parameter_points[destination].update(receiver_values)
                            if len(parameter_points[destination]) != before:
                                changed = True
                        callee_returned = return_points.get(target_key, set())
                        if result_variable and callee_returned:
                            local_points[result_variable].update(callee_returned)
                            return_events.add(
                                (
                                    target,
                                    target_call_string,
                                    (function_id, call_string, result_variable),
                                    call.line,
                                    call.column,
                                )
                            )
                    self._apply_alias_constraints(
                        context,
                        call_string,
                        local_points,
                        alias_events,
                    )

                function_returned: set[str] = set()
                for variable in context.return_variables:
                    function_returned.update(local_points.get(variable, set()))
                return_key = (function_id, call_string)
                before_return = len(return_points[return_key])
                return_points[return_key].update(function_returned)
                if len(return_points[return_key]) != before_return:
                    changed = True
                for variable, objects in local_points.items():
                    key = (function_id, call_string, variable)
                    before_observed = len(observed_points[key])
                    observed_points[key].update(objects)
                    if len(observed_points[key]) != before_observed:
                        changed = True

            result.points_to_iterations = iteration
            if not changed:
                break
        else:
            truncated = True

        result.points_to_contexts = len(active_contexts)
        result.points_to_allocations = len(allocation_facts)
        result.points_to_edges = sum(len(objects) for objects in observed_points.values())
        result.points_to_alias_edges = len(alias_events)
        result.points_to_argument_edges = len(argument_events)
        result.points_to_return_edges = len(return_events)
        result.points_to_receiver_calls = len(rta_events)
        result.points_to_direct_calls = len(direct_events)
        result.points_to_truncated = truncated
        result.rta_edges = len(rta_events)
        if truncated:
            result.warnings.append(
                "JVM source points-to analysis hit its context or iteration bound"
            )

        for allocation in allocation_facts.values():
            result.relationships.append(
                SemanticRelationship(
                    source=allocation.node_id,
                    target=allocation.type_id,
                    kind="allocation-type",
                    repository_id=allocation.repository_id,
                    file_path=allocation.file_path,
                    line=allocation.line,
                    confidence=0.91,
                    provider="codeguard-jvm-points-to",
                    fidelity="source-context-bounded-points-to",
                )
            )
        for var_key, object_ids in observed_points.items():
            point_context = functions[var_key[0]]
            for allocation_id in sorted(object_ids):
                allocation_for_edge = allocation_facts.get(allocation_id)
                result.relationships.append(
                    SemanticRelationship(
                        source=self._points_variable_node(var_key),
                        target=allocation_id,
                        kind="source-points-to",
                        repository_id=point_context.ast.repository_id,
                        file_path=point_context.ast.module_path,
                        line=allocation_for_edge.line if allocation_for_edge else 0,
                        confidence=0.87,
                        provider="codeguard-jvm-points-to",
                        fidelity="source-context-bounded-points-to",
                    )
                )
        for alias_target, alias_source, line in sorted(alias_events):
            alias_context = functions[alias_target[0]]
            result.relationships.append(
                SemanticRelationship(
                    source=self._points_variable_node(alias_source),
                    target=self._points_variable_node(alias_target),
                    kind="points-to-alias",
                    repository_id=alias_context.ast.repository_id,
                    file_path=alias_context.ast.module_path,
                    line=line,
                    confidence=0.86,
                    provider="codeguard-jvm-points-to",
                    fidelity="source-context-bounded-points-to",
                )
            )
        for argument_source, argument_target, line, _ in sorted(argument_events):
            argument_context = functions[argument_source[0]]
            result.relationships.append(
                SemanticRelationship(
                    source=self._points_variable_node(argument_source),
                    target=self._points_variable_node(argument_target),
                    kind="points-to-argument",
                    repository_id=argument_context.ast.repository_id,
                    file_path=argument_context.ast.module_path,
                    line=line,
                    confidence=0.88,
                    provider="codeguard-jvm-points-to",
                    fidelity="source-context-bounded-points-to",
                )
            )
        for callee_id, callee_context, caller_variable, line, _ in sorted(return_events):
            return_context = functions[caller_variable[0]]
            result.relationships.append(
                SemanticRelationship(
                    source=self._points_return_node(callee_id, callee_context),
                    target=self._points_variable_node(caller_variable),
                    kind="points-to-return",
                    repository_id=return_context.ast.repository_id,
                    file_path=return_context.ast.module_path,
                    line=line,
                    confidence=0.88,
                    provider="codeguard-jvm-points-to",
                    fidelity="source-context-bounded-points-to",
                )
            )
        for caller_id, callee_id, file_path, line in sorted(rta_events):
            caller_context = functions[caller_id]
            result.relationships.append(
                SemanticRelationship(
                    source=caller_id,
                    target=callee_id,
                    kind="rta-call",
                    repository_id=caller_context.ast.repository_id,
                    file_path=file_path,
                    line=line,
                    dispatch="points-to-receiver",
                    confidence=0.91,
                    provider="codeguard-jvm-points-to",
                    fidelity="source-context-bounded-points-to",
                )
            )
        for caller_id, callee_id, file_path, line in sorted(direct_events):
            caller_context = functions[caller_id]
            result.relationships.append(
                SemanticRelationship(
                    source=caller_id,
                    target=callee_id,
                    kind="points-to-call",
                    repository_id=caller_context.ast.repository_id,
                    file_path=file_path,
                    line=line,
                    dispatch="source-owner-descriptor",
                    confidence=0.89,
                    provider="codeguard-jvm-points-to",
                    fidelity="source-context-bounded-points-to",
                )
            )

    def _points_functions(self, asts: list[FileAST]) -> dict[str, _PointsFunction]:
        contexts: dict[str, _PointsFunction] = {}
        for ast in asts:
            try:
                lines = Path(ast.file_path).read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError):
                continue
            for definition in ast.functions:
                node_id = definition.symbol_id or definition.callable_name
                start = max(1, definition.line_start)
                end = min(len(lines), definition.line_end)
                body = "\n".join(lines[start - 1 : end])
                context = _PointsFunction(
                    node_id=node_id,
                    definition=definition,
                    ast=ast,
                )
                allocation_keys: set[tuple[str, str, int]] = set()
                patterns = (
                    [self._JAVA_BINDING]
                    if ast.language == Language.JAVA
                    else [
                        self._KOTLIN_BINDING,
                        self._KOTLIN_INFERRED_BINDING,
                    ]
                )
                for pattern in patterns:
                    for match in pattern.finditer(body):
                        line = start + body.count("\n", 0, match.start())
                        variable = match.group("variable")
                        runtime = match.group("runtime")
                        key = (variable, runtime, line)
                        if key in allocation_keys:
                            continue
                        allocation_keys.add(key)
                        context.allocations.append(
                            _AllocationTemplate(variable, runtime, line, match.start())
                        )
                return_pattern = (
                    self._RETURN_JAVA_ALLOCATION
                    if ast.language == Language.JAVA
                    else self._RETURN_KOTLIN_ALLOCATION
                )
                for match in return_pattern.finditer(body):
                    line = start + body.count("\n", 0, match.start())
                    context.allocations.append(
                        _AllocationTemplate(
                            self._RETURN_VALUE,
                            match.group("runtime"),
                            line,
                            match.start(),
                        )
                    )
                    context.return_variables.add(self._RETURN_VALUE)
                for match in self._ALIAS_BINDING.finditer(body):
                    line = start + body.count("\n", 0, match.start())
                    context.aliases.append((match.group("target"), match.group("source"), line))
                context.return_variables.update(
                    match.group("variable") for match in self._RETURN_VARIABLE.finditer(body)
                )
                context.calls = sorted(
                    [
                        call
                        for call in ast.calls
                        if definition.line_start <= call.line <= definition.line_end
                        and (
                            call.caller_symbol_id == node_id
                            or call.in_function == definition.name
                            or call.in_function == definition.qualified_name
                        )
                    ],
                    key=lambda call: (call.line, call.column),
                )
                for call in context.calls:
                    result = self._call_result_variable(lines, call)
                    if result:
                        context.call_results[(call.line, call.column, call.callee)] = result
                        if result == self._RETURN_VALUE:
                            context.return_variables.add(result)
                contexts[node_id] = context
        return contexts

    @staticmethod
    def _call_result_variable(lines: list[str], call: CallSite) -> str:
        if call.line < 1 or call.line > len(lines):
            return ""
        line = lines[call.line - 1]
        prefix = line[: max(0, min(len(line), call.column))]
        boundary = max(prefix.rfind(";"), prefix.rfind("{"), prefix.rfind("}"))
        statement = prefix[boundary + 1 :]
        if re.search(r"\breturn\s*$", statement):
            return JvmSemanticAnalyzer._RETURN_VALUE
        if "=" not in statement:
            return ""
        left = statement.rsplit("=", 1)[0]
        identifiers = re.findall(r"[A-Za-z_$][\w$]*", left)
        return identifiers[-1] if identifiers else ""

    @staticmethod
    def _apply_alias_constraints(
        context: _PointsFunction,
        call_string: _CallString,
        local_points: dict[str, set[str]],
        events: set[tuple[_VarKey, _VarKey, int]],
    ) -> None:
        changed = True
        while changed:
            changed = False
            for target, source, line in context.aliases:
                values = local_points.get(source, set())
                before = len(local_points[target])
                local_points[target].update(values)
                if len(local_points[target]) != before:
                    changed = True
                if values:
                    events.add(
                        (
                            (context.node_id, call_string, target),
                            (context.node_id, call_string, source),
                            line,
                        )
                    )

    def _points_call_targets(
        self,
        call: CallSite,
        context: _PointsFunction,
        local_points: dict[str, set[str]],
        allocation_facts: dict[str, _AllocationFact],
        functions: dict[str, _PointsFunction],
        functions_by_name: dict[str, list[str]],
        functions_by_file: dict[tuple[str, str], list[str]],
        type_for_function: dict[str, str],
        type_candidates: dict[tuple[str, str], list[str]],
        qualified_types: dict[str, list[str]],
        class_by_id: dict[str, tuple[FileAST, ClassDef]],
        methods: dict[tuple[str, str], list[FunctionDef]],
        parents: dict[str, set[str]],
    ) -> tuple[set[str], bool, bool]:
        if call.receiver:
            runtime_types = {
                allocation_facts[allocation].type_id
                for allocation in local_points.get(call.receiver, set())
                if allocation in allocation_facts
            }
            if runtime_types:
                targets = {
                    target
                    for type_id in runtime_types
                    for target in [
                        self._dispatch_target_for_type(
                            type_id,
                            call,
                            methods,
                            parents,
                        )
                    ]
                    if target is not None
                }
                return targets, bool(targets), False

            if call.receiver[0].isupper():
                owner = self._resolve_type(
                    type_candidates,
                    class_by_id,
                    context.ast,
                    self._simple_type(call.receiver),
                    qualified_types,
                )
                if owner is not None:
                    target = self._dispatch_target_for_type(
                        owner,
                        call,
                        methods,
                        parents,
                    )
                    if target is not None:
                        return {target}, False, True

            declared = call.receiver_type
            if declared:
                owner = self._resolve_type(
                    type_candidates,
                    class_by_id,
                    context.ast,
                    self._simple_type(declared),
                    qualified_types,
                )
                if owner is not None:
                    candidates = set(
                        self._dispatch_targets(
                            owner,
                            call,
                            class_by_id,
                            methods,
                            parents,
                        )
                    )
                    if len(candidates) == 1:
                        return candidates, False, False
            return set(), False, False

        same_type = type_for_function.get(context.node_id)
        if same_type is not None:
            target = self._dispatch_target_for_type(
                same_type,
                call,
                methods,
                parents,
            )
            if target is not None:
                return {target}, False, True
        file_candidates = functions_by_file.get((context.definition.file_path, call.callee), [])
        selected = self._select_points_target(call, file_candidates, functions)
        if selected is not None:
            return {selected}, False, True
        selected = self._select_points_target(
            call,
            functions_by_name.get(call.callee, []),
            functions,
        )
        return ({selected}, False, True) if selected is not None else (set(), False, False)

    @staticmethod
    def _select_points_target(
        call: CallSite,
        candidate_ids: list[str],
        functions: dict[str, _PointsFunction],
    ) -> str | None:
        scored = [
            (score, candidate_id)
            for candidate_id in dict.fromkeys(candidate_ids)
            if candidate_id in functions
            for score in [jvm_overload_score(call, functions[candidate_id].definition)]
            if score is not None
        ]
        if not scored:
            return None
        best = max(score for score, _ in scored)
        winners = [candidate for score, candidate in scored if score == best]
        return winners[0] if len(winners) == 1 else None

    def _points_for_expression(
        self,
        expression: str,
        context: _PointsFunction,
        call_string: _CallString,
        local_points: dict[str, set[str]],
        allocation_facts: dict[str, _AllocationFact],
        type_candidates: dict[tuple[str, str], list[str]],
        qualified_types: dict[str, list[str]],
        class_by_id: dict[str, tuple[FileAST, ClassDef]],
        line: int,
        argument_index: int,
    ) -> set[str]:
        variable = self._simple_expression_variable(expression)
        if variable:
            return set(local_points.get(variable, set()))
        allocation = self._JAVA_NEW.search(expression)
        if allocation is None:
            allocation = re.search(
                r"^\s*(?P<runtime>[A-Z][\w.$]*)\s*\(",
                expression,
            )
        if allocation is None:
            return set()
        runtime = allocation.group("runtime")
        type_id = self._resolve_type(
            type_candidates,
            class_by_id,
            context.ast,
            self._simple_type(runtime),
            qualified_types,
        )
        if type_id is None:
            return set()
        template = _AllocationTemplate(
            f"<argument:{argument_index}>",
            runtime,
            line,
            argument_index,
        )
        fact = self._allocation_fact(context, call_string, template, type_id)
        allocation_facts.setdefault(fact.node_id, fact)
        return {fact.node_id}

    @staticmethod
    def _simple_expression_variable(expression: str) -> str:
        candidate = expression.strip().removesuffix(";")
        return candidate if re.fullmatch(r"[A-Za-z_$][\w$]*", candidate) else ""

    def _allocation_fact(
        self,
        context: _PointsFunction,
        call_string: _CallString,
        template: _AllocationTemplate,
        type_id: str,
    ) -> _AllocationFact:
        context_id = self._points_context_id(call_string)
        digest = hashlib.sha256(
            (
                f"{context.node_id}\0{context_id}\0{template.line}\0"
                f"{template.site}\0{template.variable}\0{type_id}"
            ).encode()
        ).hexdigest()
        return _AllocationFact(
            node_id=f"source-allocation:sha256:{digest}",
            type_id=type_id,
            type_name=template.type_name,
            function_id=context.node_id,
            context=call_string,
            variable=template.variable,
            file_path=context.ast.module_path or context.ast.file_path,
            repository_id=context.ast.repository_id,
            line=template.line,
        )

    def _next_points_context(
        self,
        current: _CallString,
        context: _PointsFunction,
        call: CallSite,
    ) -> _CallString:
        site = (
            f"{context.node_id}@{context.ast.module_path or call.file_path}:"
            f"{call.line}:{call.column}:{call.callee}"
        )
        return (*current, site)[-self.points_to_context_depth :]

    @staticmethod
    def _points_context_id(call_string: _CallString) -> str:
        if not call_string:
            return "root"
        return hashlib.sha256("|".join(call_string).encode()).hexdigest()[:12]

    @classmethod
    def _points_variable_node(cls, variable: _VarKey) -> str:
        return f"source-variable:{variable[0]}:{cls._points_context_id(variable[1])}:{variable[2]}"

    @classmethod
    def _points_return_node(cls, function: str, call_string: _CallString) -> str:
        return f"source-return:{function}:{cls._points_context_id(call_string)}"

    def _bindings(self, ast: FileAST) -> tuple[dict[str, tuple[str, str]], set[str]]:
        try:
            text = Path(ast.file_path).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return {}, set()
        pattern = self._JAVA_BINDING if ast.language == Language.JAVA else self._KOTLIN_BINDING
        bindings: dict[str, tuple[str, str]] = {}
        instantiated_names: set[str] = set()
        for match in pattern.finditer(text):
            declared = self._simple_type(match.group("declared"))
            runtime = self._simple_type(match.group("runtime"))
            bindings[match.group("variable")] = (declared, runtime)
            instantiated_names.add(runtime)
        if ast.language == Language.JAVA:
            instantiated_names.update(
                self._simple_type(match.group("runtime")) for match in self._JAVA_NEW.finditer(text)
            )
        return bindings, instantiated_names

    @staticmethod
    def _dispatch_targets(
        declared_id: str,
        call: CallSite,
        class_by_id: dict[str, tuple[FileAST, ClassDef]],
        methods: dict[tuple[str, str], list[FunctionDef]],
        parents: dict[str, set[str]],
    ) -> list[str]:
        def subtype(candidate: str) -> bool:
            pending = [candidate]
            seen: set[str] = set()
            while pending:
                current = pending.pop()
                if current == declared_id:
                    return True
                if current in seen:
                    continue
                seen.add(current)
                pending.extend(parents.get(current, set()))
            return False

        targets = {
            target
            for type_id in class_by_id
            if subtype(type_id)
            for target in [
                JvmSemanticAnalyzer._dispatch_target_for_type(
                    type_id,
                    call,
                    methods,
                    parents,
                )
            ]
            if target is not None
        }
        return sorted(targets)

    @staticmethod
    def _dispatch_target_for_type(
        type_id: str,
        call: CallSite,
        methods: dict[tuple[str, str], list[FunctionDef]],
        parents: dict[str, set[str]] | None = None,
    ) -> str | None:
        current_level = {type_id}
        seen: set[str] = set()
        while current_level:
            candidates = [
                method
                for owner in sorted(current_level)
                for method in methods.get((owner, call.callee), [])
            ]
            scored = [
                (score, method)
                for method in candidates
                if (score := jvm_overload_score(call, method)) is not None
            ]
            if scored:
                best = max(score for score, _ in scored)
                winners = [method for score, method in scored if score == best]
                identities = {method.symbol_id or method.callable_name for method in winners}
                return next(iter(identities)) if len(identities) == 1 else None
            seen.update(current_level)
            current_level = {
                parent
                for owner in current_level
                for parent in (parents or {}).get(owner, set())
                if parent not in seen
            }
        return None

    @staticmethod
    def _caller_symbol(ast: FileAST, in_function: str | None) -> str | None:
        if not in_function:
            return None
        for function in ast.functions:
            if function.name == in_function or function.qualified_name == in_function:
                return function.symbol_id or function.qualified_name
        return None

    @staticmethod
    def _simple_type(value: str) -> str:
        value = re.sub(r"<.*>", "", value).strip()
        value = value.removesuffix("()").strip()
        return value.rsplit(".", 1)[-1]

    @staticmethod
    def _type_id(ast: FileAST, name: str) -> str:
        module = ast.module_path or Path(ast.file_path).name
        return (
            f"repo:{ast.repository_id}:jvm-type:{module}::{JvmSemanticAnalyzer._simple_type(name)}"
        )

    @classmethod
    def _qualified_type_name(cls, ast: FileAST, name: str) -> str:
        try:
            text = Path(ast.file_path).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            text = ""
        package = cls._PACKAGE.search(text)
        simple = cls._simple_type(name)
        return f"{package.group('package')}.{simple}" if package else simple

    @staticmethod
    def _resolve_type(
        type_candidates: dict[tuple[str, str], list[str]],
        class_by_id: dict[str, tuple[FileAST, ClassDef]],
        ast: FileAST,
        simple_name: str,
        qualified_types: dict[str, list[str]] | None = None,
    ) -> str | None:
        if qualified_types is not None:
            imported_names = {
                imported
                for item in ast.imports
                for imported in [item.module, *item.names]
                if imported == simple_name or imported.endswith(f".{simple_name}")
            }
            imported_candidates = {
                candidate
                for imported in imported_names
                for candidate in qualified_types.get(imported, [])
            }
            if len(imported_candidates) == 1:
                return next(iter(imported_candidates))

        candidates = type_candidates.get((ast.repository_id, simple_name), [])
        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            global_candidates = {
                candidate
                for (repository_id, name), values in type_candidates.items()
                if name == simple_name and repository_id != ast.repository_id
                for candidate in values
            }
            return next(iter(global_candidates)) if len(global_candidates) == 1 else None

        # Prefer a declaration in the same source file, then the same package
        # directory. If ambiguity remains, emit no edge instead of inventing a
        # binding. A compiler-backed SCIP relation can still resolve it.
        same_file = [
            candidate
            for candidate in candidates
            if class_by_id[candidate][0].module_path == ast.module_path
        ]
        if len(same_file) == 1:
            return same_file[0]
        package = Path(ast.module_path).parent
        same_package = [
            candidate
            for candidate in candidates
            if Path(class_by_id[candidate][0].module_path).parent == package
        ]
        if len(same_package) == 1:
            return same_package[0]
        return None

    @staticmethod
    def _relationship(
        source: str,
        target: str,
        kind: str,
        ast: FileAST,
        confidence: float,
        line: int = 0,
    ) -> SemanticRelationship:
        return SemanticRelationship(
            source=source,
            target=target,
            kind=kind,
            repository_id=ast.repository_id,
            file_path=ast.module_path or ast.file_path,
            line=line,
            confidence=confidence,
            provider="codeguard-jvm-source",
            fidelity="source-heuristic",
        )
