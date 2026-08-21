"""Spring DI, bean selection, proxy, Reactor, and coroutine overlays."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from codeguard.models import (
    CallSite,
    ClassDef,
    FileAST,
    FrameworkAnalysisSummary,
    FunctionDef,
    Language,
    SemanticRelationship,
)
from codeguard.semantic.signatures import jvm_overload_score


@dataclass
class SpringModelBundle:
    summary: FrameworkAnalysisSummary
    relationships: list[SemanticRelationship] = field(default_factory=list)


@dataclass(frozen=True)
class _InjectionBinding:
    name: str
    declared_type: str
    qualifier: str = ""


@dataclass
class _TypeFact:
    ast: FileAST
    cls: ClassDef
    source: str
    package: str
    module_id: str
    annotations: tuple[str, ...]

    @property
    def repository_id(self) -> str:
        return self.ast.repository_id


@dataclass
class _BeanCandidate:
    definition: _TypeFact
    implementation: _TypeFact | None
    declared_type: str
    names: frozenset[str]
    primary: bool
    conditions: tuple[str, ...]
    factory: FunctionDef | None = None

    @property
    def condition(self) -> str:
        return " && ".join(self.conditions)

    @property
    def display_name(self) -> str:
        return sorted(self.names)[0]


@dataclass
class _DiscoveryIndex:
    imported_types: dict[str, set[str]] = field(default_factory=dict)
    scanned_packages: dict[str, set[str]] = field(default_factory=dict)

    def allows(self, consumer_repository: str, bean: _BeanCandidate) -> bool:
        if consumer_repository == bean.definition.repository_id:
            return True
        annotations = {
            SpringModelAnalyzer._annotation_name(item) for item in bean.definition.annotations
        }
        if "@AutoConfiguration" in annotations:
            return True
        imported = self.imported_types.get(consumer_repository, set())
        if bean.definition.cls.name in imported:
            return True
        scanned = self.scanned_packages.get(consumer_repository, set())
        return any(
            bean.definition.package == package or bean.definition.package.startswith(f"{package}.")
            for package in scanned
        )


@dataclass
class _ScopeIndex:
    file_modules: dict[str, str] = field(default_factory=dict)
    module_edges: dict[str, set[str]] = field(default_factory=dict)
    repository_edges: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        relationships: list[SemanticRelationship],
        repository_dependencies: dict[str, list[str]],
    ) -> _ScopeIndex:
        index = cls()
        module_consumers: dict[str, set[str]] = {}
        module_providers: dict[str, set[str]] = {}
        repository_consumers: dict[str, set[str]] = {}
        repository_providers: dict[str, set[str]] = {}
        for consumer, providers in repository_dependencies.items():
            index.repository_edges.setdefault(consumer, set()).update(providers)
        for relationship in relationships:
            if relationship.kind == "member-of-module":
                index.file_modules[relationship.source] = relationship.target
            elif relationship.kind == "module-dependency":
                index.module_edges.setdefault(relationship.source, set()).add(relationship.target)
            elif relationship.kind == "depends-on-jvm-artifact":
                module_consumers.setdefault(relationship.target, set()).add(relationship.source)
            elif relationship.kind == "resolved-jvm-provider":
                module_providers.setdefault(relationship.source, set()).add(relationship.target)
            elif relationship.kind == "repository-depends-on-jvm-artifact":
                repository_consumers.setdefault(relationship.target, set()).add(
                    relationship.source.removeprefix("repository:")
                )
            elif relationship.kind == "resolved-jvm-provider-repository":
                repository_providers.setdefault(relationship.source, set()).add(
                    relationship.target.removeprefix("repository:")
                )
        for artifact, consumers in module_consumers.items():
            for consumer in consumers:
                index.module_edges.setdefault(consumer, set()).update(
                    module_providers.get(artifact, set())
                )
        for artifact, consumers in repository_consumers.items():
            for consumer in consumers:
                index.repository_edges.setdefault(consumer, set()).update(
                    repository_providers.get(artifact, set())
                )
        return index

    def module_for(self, ast: FileAST) -> str:
        return self.file_modules.get(
            f"repo:{ast.repository_id}:file:{ast.module_path}",
            "",
        )

    def allows(self, consumer: FileAST, provider: FileAST) -> bool:
        consumer_module = self.module_for(consumer)
        provider_module = self.module_for(provider)
        if consumer.repository_id == provider.repository_id:
            if not consumer_module or not provider_module:
                return True
            return provider_module in self._reachable(
                self.module_edges,
                consumer_module,
            )
        if consumer_module and provider_module:
            reachable_modules = self._reachable(self.module_edges, consumer_module)
            if provider_module in reachable_modules:
                return True
        return provider.repository_id in self._reachable(
            self.repository_edges,
            consumer.repository_id,
        )

    @staticmethod
    def _reachable(graph: dict[str, set[str]], start: str) -> set[str]:
        seen = {start}
        pending = [start]
        while pending:
            current = pending.pop()
            for target in graph.get(current, set()):
                if target in seen:
                    continue
                seen.add(target)
                pending.append(target)
        return seen


class SpringModelAnalyzer:
    """Resolve common Spring bean, proxy, and asynchronous edges conservatively."""

    _COMPONENTS = {
        "@AutoConfiguration",
        "@Component",
        "@Configuration",
        "@Controller",
        "@Repository",
        "@RestController",
        "@Service",
    }
    _CONDITIONS = {
        "@Conditional",
        "@ConditionalOnBean",
        "@ConditionalOnClass",
        "@ConditionalOnExpression",
        "@ConditionalOnJava",
        "@ConditionalOnJndi",
        "@ConditionalOnMissingBean",
        "@ConditionalOnMissingClass",
        "@ConditionalOnNotWebApplication",
        "@ConditionalOnProperty",
        "@ConditionalOnResource",
        "@ConditionalOnSingleCandidate",
        "@ConditionalOnWebApplication",
        "@Profile",
    }
    _JAVA_FIELD = re.compile(
        r"(?P<annotations>(?:(?:@[\w.$:]+(?:\([^)]*\))?)\s+)*)"
        r"(?:private|protected|public)?\s*(?:final\s+)?"
        r"(?P<type>[A-Z][\w.$<>?]*)\s+(?P<name>[a-zA-Z_$][\w$]*)\s*;"
    )
    _JAVA_CONSTRUCTOR_PARAM = re.compile(
        r"^\s*(?P<annotations>(?:(?:@[\w.$:]+(?:\([^)]*\))?)\s+)*)"
        r"(?:final\s+)?(?P<type>[A-Z][\w.$<>?]*)\s+"
        r"(?P<name>[a-zA-Z_$][\w$]*)\s*$"
    )
    _KOTLIN_BINDING = re.compile(
        r"(?P<annotations>(?:(?:@[\w.$:]+(?:\([^)]*\))?)\s+)*)"
        r"(?:private|protected|public|internal|lateinit|override|open|final|\s)*"
        r"(?:val|var)\s+(?P<name>[a-zA-Z_$][\w$]*)\s*:\s*"
        r"(?P<type>[A-Z][\w.$<>?]*)"
    )
    _REACTIVE_CALLS = {"flatMap", "map", "onErrorResume", "switchIfEmpty", "then"}

    def analyze(
        self,
        file_asts: list[FileAST],
        repository_dependencies: dict[str, list[str]] | None = None,
        semantic_relationships: list[SemanticRelationship] | None = None,
    ) -> SpringModelBundle:
        summary = FrameworkAnalysisSummary(enabled=True)
        relationships: list[SemanticRelationship] = []
        sources = self._read_sources(file_asts, summary)
        scope = _ScopeIndex.build(
            semantic_relationships or [],
            repository_dependencies or {},
        )
        facts = self._type_facts(file_asts, sources, scope)
        discovery = self._discovery_index(facts)
        beans = self._bean_candidates(facts, summary)
        self._emit_factory_edges(beans, relationships)
        summary.spring_components = sum(
            1
            for fact in facts
            if any(
                self._annotation_name(annotation) in self._COMPONENTS
                for annotation in fact.annotations
            )
        )

        for ast in file_asts:
            if ast.language not in {Language.JAVA, Language.KOTLIN}:
                continue
            source = sources.get(ast.file_path)
            if source is None:
                continue
            bindings_by_class = self._bindings_by_class(ast, source)
            bindings = {
                (class_name, binding.name): binding
                for class_name, class_bindings in bindings_by_class.items()
                for binding in class_bindings.values()
            }
            summary.bean_bindings += len(bindings)
            summary.qualified_bindings += sum(
                1 for binding in bindings.values() if binding.qualifier
            )
            function_by_id = {
                function.symbol_id or function.qualified_name: function
                for function in ast.functions
            }
            function_by_name = {function.name: function for function in ast.functions}
            for call in ast.calls:
                if not call.receiver or not call.in_function:
                    continue
                caller = function_by_id.get(call.caller_symbol_id) or function_by_name.get(
                    call.in_function
                )
                if caller is None or not caller.class_name:
                    continue
                receiver = call.receiver.rsplit(".", 1)[-1]
                binding = bindings.get((caller.class_name, receiver))
                if binding is None:
                    continue
                candidates = [
                    bean
                    for bean in beans
                    if self._bean_matches(bean, binding.declared_type, facts)
                    and scope.allows(ast, bean.definition.ast)
                    and discovery.allows(ast.repository_id, bean)
                ]
                selected, resolution = self._select_beans(binding, candidates)
                if resolution == "ambiguous":
                    summary.ambiguous_bindings += 1
                elif resolution == "primary":
                    summary.primary_resolutions += 1
                caller_id = caller.symbol_id or caller.qualified_name
                for bean in selected:
                    target = self._bean_target(call, bean, facts)
                    if target is None:
                        continue
                    confidence = self._binding_confidence(
                        resolution,
                        conditional=bool(bean.conditions),
                        cross_repository=ast.repository_id != bean.definition.repository_id,
                    )
                    relationships.append(
                        self._edge(
                            caller_id,
                            target,
                            "spring-di-call",
                            ast,
                            call.line,
                            confidence,
                            fidelity=f"framework-model-{resolution}",
                            qualifier=binding.qualifier,
                            condition=bean.condition,
                        )
                    )
                    summary.di_call_edges += 1
                    if bean.conditions:
                        summary.conditional_candidates += 1
                    if ast.repository_id != bean.definition.repository_id:
                        summary.cross_repository_di_edges += 1

            self._emit_function_overlays(ast, source, relationships, summary)
        return SpringModelBundle(summary, relationships)

    @staticmethod
    def _read_sources(
        file_asts: list[FileAST],
        summary: FrameworkAnalysisSummary,
    ) -> dict[str, str]:
        sources: dict[str, str] = {}
        for ast in file_asts:
            if ast.language not in {Language.JAVA, Language.KOTLIN}:
                continue
            try:
                sources[ast.file_path] = Path(ast.file_path).read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                summary.warnings.append(f"{ast.file_path}: {error}")
        return sources

    def _type_facts(
        self,
        file_asts: list[FileAST],
        sources: dict[str, str],
        scope: _ScopeIndex,
    ) -> list[_TypeFact]:
        facts: list[_TypeFact] = []
        for ast in file_asts:
            source = sources.get(ast.file_path)
            if source is None:
                continue
            package_match = re.search(r"(?m)^\s*package\s+([\w.]+)", source)
            package = package_match.group(1) if package_match else ""
            for cls in ast.classes:
                facts.append(
                    _TypeFact(
                        ast,
                        cls,
                        source,
                        package,
                        scope.module_for(ast),
                        tuple(cls.decorators),
                    )
                )
        return facts

    def _discovery_index(self, facts: list[_TypeFact]) -> _DiscoveryIndex:
        result = _DiscoveryIndex()
        for fact in facts:
            repository = fact.repository_id
            for annotation in fact.annotations:
                name = self._annotation_name(annotation)
                if name in {"@Import", "@ImportAutoConfiguration"}:
                    result.imported_types.setdefault(repository, set()).update(
                        re.findall(r"\b([A-Z][\w$]*)\s*\.class\b", annotation)
                    )
                if name in {"@ComponentScan", "@SpringBootApplication"}:
                    result.scanned_packages.setdefault(repository, set()).update(
                        self._annotation_strings(annotation)
                    )
        return result

    def _bean_candidates(
        self,
        facts: list[_TypeFact],
        summary: FrameworkAnalysisSummary,
    ) -> list[_BeanCandidate]:
        beans: list[_BeanCandidate] = []
        for fact in facts:
            annotation_names = {
                self._annotation_name(annotation) for annotation in fact.annotations
            }
            component_annotations = [
                annotation
                for annotation in fact.annotations
                if self._annotation_name(annotation) in self._COMPONENTS
            ]
            if component_annotations:
                names = {self._default_bean_name(fact.cls.name)}
                for annotation in component_annotations:
                    names.update(self._annotation_strings(annotation))
                names.update(self._qualifiers(fact.annotations))
                beans.append(
                    _BeanCandidate(
                        fact,
                        fact,
                        fact.cls.name,
                        frozenset(names),
                        "@Primary" in annotation_names,
                        self._conditions(fact.annotations),
                    )
                )
            for method in fact.cls.methods:
                method_names = {
                    self._annotation_name(annotation) for annotation in method.decorators
                }
                if "@Bean" not in method_names:
                    continue
                summary.bean_factories += 1
                bean_annotation = next(
                    annotation
                    for annotation in method.decorators
                    if self._annotation_name(annotation) == "@Bean"
                )
                names = {method.name, *self._annotation_strings(bean_annotation)}
                names.update(self._qualifiers(method.decorators))
                implementation_name = self._infer_factory_implementation(fact, method)
                implementation = self._unique_type(
                    facts,
                    implementation_name or self._simple_type(method.return_type),
                    fact.repository_id,
                )
                beans.append(
                    _BeanCandidate(
                        fact,
                        implementation,
                        self._simple_type(method.return_type),
                        frozenset(names),
                        "@Primary" in annotation_names or "@Primary" in method_names,
                        self._conditions(fact.annotations) + self._conditions(method.decorators),
                        method,
                    )
                )
        return beans

    def _emit_factory_edges(
        self,
        beans: list[_BeanCandidate],
        relationships: list[SemanticRelationship],
    ) -> None:
        for bean in beans:
            if bean.factory is None:
                continue
            factory_id = bean.factory.symbol_id or bean.factory.callable_name
            bean_node = (
                f"spring-bean:{bean.definition.repository_id}:"
                f"{quote(bean.definition.ast.module_path, safe='')}:"
                f"{quote(bean.display_name, safe='')}"
            )
            relationships.append(
                self._edge(
                    factory_id,
                    bean_node,
                    "spring-bean-factory",
                    bean.definition.ast,
                    bean.factory.line_start,
                    0.96,
                    fidelity="framework-model-bean-factory",
                    qualifier=bean.display_name,
                    condition=bean.condition,
                )
            )
            if bean.implementation is None:
                continue
            relationships.append(
                self._edge(
                    bean_node,
                    self._type_id(bean.implementation),
                    "spring-bean-type",
                    bean.definition.ast,
                    bean.factory.line_start,
                    0.9,
                    fidelity="framework-model-bean-factory",
                    qualifier=bean.display_name,
                    condition=bean.condition,
                )
            )

    def _bindings_by_class(
        self,
        ast: FileAST,
        source: str,
    ) -> dict[str, dict[str, _InjectionBinding]]:
        result: dict[str, dict[str, _InjectionBinding]] = {}
        lines = source.splitlines()
        for cls in ast.classes:
            snippet = "\n".join(lines[max(cls.line_start - 1, 0) : cls.line_end])
            bindings: dict[str, _InjectionBinding] = {}
            if ast.language == Language.JAVA:
                for match in self._JAVA_FIELD.finditer(snippet):
                    binding = self._binding_from_match(match)
                    bindings[binding.name] = binding
                constructor = re.compile(
                    rf"\b{re.escape(cls.name)}\s*\((?P<params>[^)]*(?:\)[^)]*)?)\)"
                )
                for declaration in constructor.finditer(snippet):
                    for parameter in self._split_parameters(declaration.group("params")):
                        parameter_match = self._JAVA_CONSTRUCTOR_PARAM.match(parameter)
                        if parameter_match is None:
                            continue
                        binding = self._binding_from_match(parameter_match)
                        bindings[binding.name] = binding
            else:
                for match in self._KOTLIN_BINDING.finditer(snippet):
                    binding = self._binding_from_match(match)
                    bindings[binding.name] = binding
            result[cls.name] = bindings
        return result

    def _binding_from_match(self, match: re.Match[str]) -> _InjectionBinding:
        annotations = match.groupdict().get("annotations", "") or ""
        return _InjectionBinding(
            match.group("name"),
            self._simple_type(match.group("type")),
            self._injection_qualifier(annotations),
        )

    @staticmethod
    def _split_parameters(value: str) -> list[str]:
        result: list[str] = []
        start = 0
        depth = 0
        for index, character in enumerate(value):
            if character in "(<[{":
                depth += 1
            elif character in ")>]}" and depth:
                depth -= 1
            elif character == "," and depth == 0:
                result.append(value[start:index])
                start = index + 1
        result.append(value[start:])
        return [item.strip() for item in result if item.strip()]

    def _bean_matches(
        self,
        bean: _BeanCandidate,
        declared_type: str,
        facts: list[_TypeFact],
    ) -> bool:
        if bean.declared_type == declared_type:
            return True
        return bool(
            bean.implementation
            and self._is_assignable(bean.implementation, declared_type, facts, set())
        )

    def _is_assignable(
        self,
        fact: _TypeFact,
        declared_type: str,
        facts: list[_TypeFact],
        visited: set[tuple[str, str, str]],
    ) -> bool:
        identity = (fact.repository_id, fact.ast.module_path, fact.cls.name)
        if identity in visited:
            return False
        if fact.cls.name == declared_type:
            return True
        parents = {self._simple_type(parent) for parent in fact.cls.base_classes}
        if declared_type in parents:
            return True
        visited = {*visited, identity}
        return any(
            self._is_assignable(parent, declared_type, facts, visited)
            for name in parents
            for parent in facts
            if parent.cls.name == name
        )

    @staticmethod
    def _select_beans(
        binding: _InjectionBinding,
        candidates: list[_BeanCandidate],
    ) -> tuple[list[_BeanCandidate], str]:
        if binding.qualifier:
            qualified = [
                candidate for candidate in candidates if binding.qualifier in candidate.names
            ]
            return qualified, "qualifier"
        if len(candidates) <= 1:
            return candidates, "single"
        unconditional_primaries = [
            candidate for candidate in candidates if candidate.primary and not candidate.conditions
        ]
        if len(unconditional_primaries) == 1:
            return unconditional_primaries, "primary"
        named = [candidate for candidate in candidates if binding.name in candidate.names]
        if len(named) == 1:
            return named, "name"
        return candidates, "ambiguous"

    def _bean_target(
        self,
        call: CallSite,
        bean: _BeanCandidate,
        facts: list[_TypeFact],
    ) -> str | None:
        targets: list[_TypeFact] = []
        if bean.implementation is not None:
            targets.append(bean.implementation)
        targets.extend(
            fact for fact in facts if fact.cls.name == bean.declared_type and fact not in targets
        )
        for fact in targets:
            target = self._select_method(
                call,
                [method for method in fact.cls.methods if method.name == call.callee],
            )
            if target is not None:
                return target
        return None

    @staticmethod
    def _select_method(call: CallSite, candidates: list[FunctionDef]) -> str | None:
        scored = [
            (score, method)
            for method in candidates
            if (score := jvm_overload_score(call, method)) is not None
        ]
        if not scored:
            return None
        best = max(score for score, _ in scored)
        winners = [method for score, method in scored if score == best]
        if len(winners) != 1:
            return None
        method = winners[0]
        return method.symbol_id or method.callable_name

    def _emit_function_overlays(
        self,
        ast: FileAST,
        source: str,
        relationships: list[SemanticRelationship],
        summary: FrameworkAnalysisSummary,
    ) -> None:
        function_by_id = {
            function.symbol_id or function.qualified_name: function for function in ast.functions
        }
        function_by_name = {function.name: function for function in ast.functions}
        for function in ast.functions:
            function_id = function.symbol_id or function.qualified_name
            annotations = {self._annotation_name(item) for item in function.decorators}
            if "@PreAuthorize" in annotations or "@Secured" in annotations:
                relationships.append(
                    self._edge(
                        f"spring-security:{function_id}",
                        function_id,
                        "security-guard",
                        ast,
                        function.line_start,
                        0.95,
                    )
                )
                summary.security_guards += 1
            if "@Transactional" in annotations:
                relationships.append(
                    self._edge(
                        f"spring-transaction:{function_id}",
                        function_id,
                        "transaction-proxy",
                        ast,
                        function.line_start,
                        0.95,
                    )
                )
                summary.transaction_boundaries += 1
            snippet = self._function_snippet(source, function.line_start, function.line_end)
            if re.search(rf"\bsuspend\s+fun\s+{re.escape(function.name)}\b", snippet):
                relationships.append(
                    self._edge(
                        function_id,
                        f"kotlin-continuation:{function_id}",
                        "coroutine-continuation",
                        ast,
                        function.line_start,
                        0.9,
                    )
                )
                summary.coroutine_edges += 1
        for call in ast.calls:
            if call.callee not in self._REACTIVE_CALLS or not call.in_function:
                continue
            caller = function_by_id.get(call.caller_symbol_id) or function_by_name.get(
                call.in_function
            )
            if caller is None:
                continue
            caller_id = caller.symbol_id or caller.qualified_name
            relationships.append(
                self._edge(
                    caller_id,
                    f"reactor:{caller_id}:{call.line}:{call.callee}",
                    "reactive-continuation",
                    ast,
                    call.line,
                    0.78,
                )
            )
            summary.reactive_edges += 1

    @staticmethod
    def _binding_confidence(
        resolution: str,
        *,
        conditional: bool,
        cross_repository: bool,
    ) -> float:
        confidence = {
            "qualifier": 0.97,
            "primary": 0.95,
            "name": 0.91,
            "single": 0.88,
            "ambiguous": 0.68,
        }.get(resolution, 0.68)
        if conditional:
            confidence -= 0.14
        if cross_repository:
            confidence -= 0.04
        return max(confidence, 0.4)

    @staticmethod
    def _annotation_name(value: str) -> str:
        match = re.match(r"@(?:\w+:)?([\w.$]+)", value.strip())
        return f"@{match.group(1).rsplit('.', 1)[-1]}" if match else ""

    @staticmethod
    def _annotation_strings(value: str) -> set[str]:
        return set(re.findall(r'["\']([^"\']+)["\']', value))

    def _conditions(self, annotations: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            re.sub(r"\s+", " ", annotation).strip()
            for annotation in annotations
            if self._annotation_name(annotation) in self._CONDITIONS
        )

    def _qualifiers(self, annotations: list[str] | tuple[str, ...]) -> set[str]:
        result: set[str] = set()
        for annotation in annotations:
            if self._annotation_name(annotation) in {"@Qualifier", "@Named"}:
                result.update(self._annotation_strings(annotation))
        return result

    def _injection_qualifier(self, annotations: str) -> str:
        for pattern in (
            r"@(?:\w+:)?(?:Qualifier|Named)\s*\(\s*[\"']([^\"']+)",
            r"@(?:\w+:)?Resource\s*\([^)]*\bname\s*=\s*[\"']([^\"']+)",
        ):
            match = re.search(pattern, annotations)
            if match:
                return match.group(1)
        return ""

    def _infer_factory_implementation(
        self,
        fact: _TypeFact,
        method: FunctionDef,
    ) -> str:
        snippet = self._function_snippet(
            fact.source,
            method.line_start,
            method.line_end,
        )
        for pattern in (
            r"\bnew\s+([A-Z][\w$]*)\s*\(",
            r"(?:\breturn\s+|=\s*)([A-Z][\w$]*)\s*\(",
        ):
            match = re.search(pattern, snippet)
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def _unique_type(
        facts: list[_TypeFact],
        name: str,
        preferred_repository: str,
    ) -> _TypeFact | None:
        if not name:
            return None
        preferred = [
            fact
            for fact in facts
            if fact.cls.name == name and fact.repository_id == preferred_repository
        ]
        if len(preferred) == 1:
            return preferred[0]
        candidates = [fact for fact in facts if fact.cls.name == name]
        return candidates[0] if len(candidates) == 1 else None

    @staticmethod
    def _default_bean_name(class_name: str) -> str:
        return class_name[:1].lower() + class_name[1:]

    @staticmethod
    def _simple_type(value: str) -> str:
        return (
            re.sub(r"<.*>", "", value)
            .removesuffix("?")
            .removesuffix("()")
            .rsplit(".", 1)[-1]
            .strip()
        )

    @staticmethod
    def _function_snippet(source: str, start: int, end: int) -> str:
        lines = source.splitlines()
        return "\n".join(lines[max(start - 1, 0) : end])

    @staticmethod
    def _type_id(fact: _TypeFact) -> str:
        module = fact.ast.module_path or Path(fact.ast.file_path).name
        return (
            f"repo:{fact.repository_id}:jvm-type:{module}::"
            f"{SpringModelAnalyzer._simple_type(fact.cls.name)}"
        )

    @staticmethod
    def _edge(
        source: str,
        target: str,
        kind: str,
        ast: FileAST,
        line: int,
        confidence: float,
        *,
        fidelity: str = "framework-model",
        qualifier: str = "",
        condition: str = "",
    ) -> SemanticRelationship:
        return SemanticRelationship(
            source=source,
            target=target,
            kind=kind,
            repository_id=ast.repository_id,
            file_path=ast.module_path or ast.file_path,
            line=line,
            qualifier=qualifier,
            condition=condition,
            confidence=confidence,
            provider="codeguard-spring-model-v2",
            fidelity=fidelity,
        )
