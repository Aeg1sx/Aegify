"""Cross-repository API attack-surface correlation.

This module deliberately stores evidence, not assumptions: frontend HTTP calls,
Spring Cloud Gateway routes, and backend endpoints remain separate records and
are connected with a match kind and confidence score.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from aegify.models import (
    AttackSurfaceLink,
    EndpointInfo,
    FileAST,
    FrontendCall,
    GatewayRoute,
    Language,
)

logger = logging.getLogger(__name__)

_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
_FETCH_RE = re.compile(
    r"\bfetch\s*\(\s*(?P<quote>['\"`])(?P<url>.*?)(?P=quote)",
    re.DOTALL,
)
_METHOD_CLIENT_RE = re.compile(
    r"\b(?P<client>axios|apiClient|httpClient|this\.http|api)"
    r"\.(?P<method>get|post|put|delete|patch|head|options)\s*\(\s*"
    r"(?P<quote>['\"`])(?P<url>.*?)(?P=quote)",
    re.DOTALL | re.IGNORECASE,
)
_AXIOS_CONFIG_RE = re.compile(
    r"\baxios\s*\(\s*\{(?P<body>.{0,1200}?)\}\s*\)",
    re.DOTALL,
)
_TEMPLATE_EXPR_RE = re.compile(r"\$\{[^}]+\}")


class AttackSurfaceAnalyzer:
    """Detect and link external API consumers to application endpoints."""

    def analyze(
        self,
        repository_roots: list[Path],
        file_asts: list[FileAST],
        endpoints: list[EndpointInfo],
        repository_ids_by_root: dict[Path, str] | None = None,
    ) -> tuple[list[FrontendCall], list[GatewayRoute], list[AttackSurfaceLink]]:
        frontend_calls = self._find_frontend_calls(file_asts)
        gateway_routes = self._find_gateway_routes(
            repository_roots,
            file_asts,
            repository_ids_by_root or {},
        )
        links = self._link(frontend_calls, gateway_routes, endpoints)
        logger.info(
            "Attack surface: %d client calls, %d gateway routes, %d links",
            len(frontend_calls),
            len(gateway_routes),
            len(links),
        )
        return frontend_calls, gateway_routes, links

    def _find_frontend_calls(self, file_asts: list[FileAST]) -> list[FrontendCall]:
        calls: list[FrontendCall] = []
        seen: set[tuple[str, int, str, str]] = set()
        for ast in file_asts:
            if ast.language not in (Language.JAVASCRIPT, Language.TYPESCRIPT):
                continue
            try:
                source = Path(ast.file_path).read_text(errors="replace")
            except OSError:
                continue

            frontend_confidence = self._frontend_confidence(ast.file_path, source)
            for match in _FETCH_RE.finditer(source):
                window = source[match.end() : match.end() + 400]
                method_match = re.search(r"\bmethod\s*:\s*['\"]([A-Za-z]+)['\"]", window)
                method = method_match.group(1).upper() if method_match else "GET"
                self._append_frontend_call(
                    calls,
                    seen,
                    ast,
                    source,
                    match.start(),
                    method,
                    match.group("url"),
                    "fetch",
                    frontend_confidence,
                )

            for match in _METHOD_CLIENT_RE.finditer(source):
                self._append_frontend_call(
                    calls,
                    seen,
                    ast,
                    source,
                    match.start(),
                    match.group("method").upper(),
                    match.group("url"),
                    match.group("client"),
                    frontend_confidence,
                )

            for match in _AXIOS_CONFIG_RE.finditer(source):
                body = match.group("body")
                url_match = re.search(
                    r"\burl\s*:\s*(?P<quote>['\"`])(?P<url>.*?)(?P=quote)",
                    body,
                    re.DOTALL,
                )
                if not url_match:
                    continue
                method_match = re.search(r"\bmethod\s*:\s*['\"]([A-Za-z]+)['\"]", body)
                method = method_match.group(1).upper() if method_match else "GET"
                self._append_frontend_call(
                    calls,
                    seen,
                    ast,
                    source,
                    match.start(),
                    method,
                    url_match.group("url"),
                    "axios",
                    frontend_confidence,
                )
        return calls

    @staticmethod
    def _frontend_confidence(file_path: str, source: str) -> float:
        path = file_path.replace("\\", "/").lower()
        if file_path.endswith((".tsx", ".jsx")):
            return 0.95
        markers = (
            "/frontend/",
            "/client/",
            "/web/",
            "/ui/",
            "/pages/",
            "/components/",
            "/src/main/resources/static/",
        )
        if any(marker in path for marker in markers):
            return 0.9
        if any(token in source for token in ("react", "vue", "@angular", "window.")):
            return 0.85
        return 0.65

    def _append_frontend_call(
        self,
        calls: list[FrontendCall],
        seen: set[tuple[str, int, str, str]],
        ast: FileAST,
        source: str,
        offset: int,
        method: str,
        raw_url: str,
        client: str,
        confidence: float,
    ) -> None:
        if method not in _HTTP_METHODS:
            return
        path, dynamic = self._normalise_client_url(raw_url)
        if not path:
            return
        line = source.count("\n", 0, offset) + 1
        key = (ast.file_path, line, method, path)
        if key in seen:
            return
        seen.add(key)
        digest = hashlib.sha256(":".join(map(str, key)).encode()).hexdigest()[:16]
        calls.append(
            FrontendCall(
                id=f"frontend:{digest}",
                path=path,
                method=method,
                file_path=ast.file_path,
                line=line,
                client=client,
                repository_id=ast.repository_id,
                dynamic=dynamic,
                confidence=confidence - (0.1 if dynamic else 0.0),
            )
        )

    @staticmethod
    def _normalise_client_url(raw_url: str) -> tuple[str, bool]:
        dynamic = bool(_TEMPLATE_EXPR_RE.search(raw_url))
        value = _TEMPLATE_EXPR_RE.sub("{dynamic}", raw_url).strip()
        if "://" in value:
            value = urlsplit(value).path
        elif not value.startswith("/"):
            # Common template: ${API_BASE}/v1/users
            slash = value.find("/")
            if slash == -1:
                return "", dynamic
            value = value[slash:]
        value = value.split("?", 1)[0].split("#", 1)[0]
        value = re.sub(r"/{2,}", "/", value)
        return (value or "/"), dynamic

    def _find_gateway_routes(
        self,
        repository_roots: list[Path],
        file_asts: list[FileAST],
        repository_ids_by_root: dict[Path, str],
    ) -> list[GatewayRoute]:
        routes: list[GatewayRoute] = []
        seen_files: set[Path] = set()
        for root in repository_roots:
            for pattern in (
                "application*.yml",
                "application*.yaml",
                "bootstrap*.yml",
                "bootstrap*.yaml",
            ):
                for path in root.rglob(pattern):
                    if path in seen_files or self._ignored_path(path):
                        continue
                    seen_files.add(path)
                    routes.extend(
                        self._parse_gateway_yaml(
                            path,
                            root,
                            file_asts,
                            repository_ids_by_root.get(root.resolve(), ""),
                        )
                    )
        routes.extend(self._parse_gateway_dsl(file_asts))

        unique: dict[tuple[str, str, tuple[str, ...]], GatewayRoute] = {}
        for route in routes:
            key = (route.repository_id, route.id, tuple(route.path_patterns))
            unique[key] = route
        return list(unique.values())

    @staticmethod
    def _ignored_path(path: Path) -> bool:
        return any(
            part
            in {
                ".git",
                ".gradle",
                ".next",
                ".venv",
                "build",
                "dist",
                "node_modules",
                "target",
                "venv",
                "vendor",
            }
            for part in path.parts
        )

    def _parse_gateway_yaml(
        self,
        path: Path,
        root: Path,
        file_asts: list[FileAST],
        repository_id: str = "",
    ) -> list[GatewayRoute]:
        try:
            source = path.read_text(errors="replace")
            data = yaml.safe_load(source) or {}
        except (OSError, yaml.YAMLError):
            return []

        repository_id = repository_id or self._repository_for_path(path, root, file_asts)
        candidates = [
            self._dig(data, "spring", "cloud", "gateway", "routes"),
            self._dig(
                data,
                "spring",
                "cloud",
                "gateway",
                "server",
                "webflux",
                "routes",
            ),
        ]
        routes: list[GatewayRoute] = []
        for configured in candidates:
            if not isinstance(configured, list):
                continue
            for index, item in enumerate(configured):
                if not isinstance(item, dict):
                    continue
                route_id = str(item.get("id") or f"route-{index}")
                predicates = item.get("predicates") or []
                filters = [self._config_item_text(v) for v in item.get("filters") or []]
                paths, methods = self._gateway_predicates(predicates)
                if not paths:
                    continue
                line = source.find(f"id: {route_id}")
                line_number = source.count("\n", 0, max(line, 0)) + 1
                routes.append(
                    GatewayRoute(
                        id=route_id,
                        uri=str(item.get("uri") or ""),
                        path_patterns=paths,
                        methods=methods,
                        filters=filters,
                        file_path=str(path),
                        line=line_number,
                        repository_id=repository_id,
                    )
                )
        return routes

    @staticmethod
    def _dig(data: Any, *keys: str) -> Any:
        current = data
        for key in keys:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    @staticmethod
    def _config_item_text(item: Any) -> str:
        if isinstance(item, str):
            return item
        if isinstance(item, dict):
            name = str(item.get("name") or "")
            args = item.get("args") or {}
            rendered = ",".join(str(value) for value in args.values())
            return f"{name}={rendered}" if rendered else name
        return str(item)

    def _gateway_predicates(self, predicates: Any) -> tuple[list[str], list[str]]:
        paths: list[str] = []
        methods: list[str] = []
        for predicate in predicates if isinstance(predicates, list) else []:
            text = self._config_item_text(predicate)
            name, _, args = text.partition("=")
            if name.lower() == "path":
                paths.extend(p.strip() for p in args.split(",") if p.strip())
            elif name.lower() == "method":
                methods.extend(m.strip().upper() for m in args.split(",") if m.strip())
        return paths, methods

    def _parse_gateway_dsl(self, file_asts: list[FileAST]) -> list[GatewayRoute]:
        routes: list[GatewayRoute] = []
        for ast in file_asts:
            if ast.language not in (Language.JAVA, Language.KOTLIN):
                continue
            try:
                source = Path(ast.file_path).read_text(errors="replace")
            except OSError:
                continue
            if "RouteLocator" not in source and ".route(" not in source:
                continue
            starts = list(re.finditer(r"\.route\s*\(\s*['\"]([^'\"]+)['\"]", source))
            for index, start in enumerate(starts):
                end = starts[index + 1].start() if index + 1 < len(starts) else len(source)
                body = source[start.start() : end]
                paths = re.findall(r"\.path\s*\(\s*['\"]([^'\"]+)['\"]", body)
                uri = re.search(r"\.uri\s*\(\s*['\"]([^'\"]+)['\"]", body)
                if not paths or not uri:
                    continue
                routes.append(
                    GatewayRoute(
                        id=start.group(1),
                        uri=uri.group(1),
                        path_patterns=paths,
                        filters=[
                            f"{name}={args.strip()}"
                            for name, args in re.findall(
                                r"\.(stripPrefix|rewritePath|prefixPath)\s*\(([^)]*)\)",
                                body,
                            )
                        ],
                        file_path=ast.file_path,
                        line=source.count("\n", 0, start.start()) + 1,
                        repository_id=ast.repository_id,
                    )
                )
        return routes

    @staticmethod
    def _repository_for_path(path: Path, root: Path, file_asts: list[FileAST]) -> str:
        for ast in file_asts:
            try:
                Path(ast.file_path).resolve().relative_to(root.resolve())
            except ValueError:
                continue
            if ast.repository_id:
                return ast.repository_id
        return root.name

    def _link(
        self,
        frontend_calls: list[FrontendCall],
        gateway_routes: list[GatewayRoute],
        endpoints: list[EndpointInfo],
    ) -> list[AttackSurfaceLink]:
        links: list[AttackSurfaceLink] = []
        for endpoint in endpoints:
            linked_frontend_calls: set[str] = set()
            for call in frontend_calls:
                match_kind = self._endpoint_match(call.path, endpoint.path)
                if not self._method_matches(call.method, endpoint.method):
                    continue
                if not match_kind:
                    match_kind = self._frontend_gateway_match(call, gateway_routes, endpoint)
                if not match_kind:
                    continue
                endpoint.called_by_frontend = True
                if call.id not in linked_frontend_calls:
                    endpoint.frontend_call_count += 1
                    linked_frontend_calls.add(call.id)
                links.append(
                    self._link_record(
                        "frontend_call", call.id, endpoint, match_kind, call.confidence
                    )
                )

            for route in gateway_routes:
                if route.methods and not any(
                    self._method_matches(method, endpoint.method) for method in route.methods
                ):
                    continue
                match_kind = self._gateway_match(route, endpoint.path)
                if not match_kind:
                    continue
                endpoint.exposed_via_gateway = True
                if route.id not in endpoint.gateway_route_ids:
                    endpoint.gateway_route_ids.append(route.id)
                confidence = 0.9 if match_kind == "gateway_transform" else 0.8
                links.append(
                    self._link_record("gateway_route", route.id, endpoint, match_kind, confidence)
                )
        return links

    def _frontend_gateway_match(
        self,
        call: FrontendCall,
        routes: list[GatewayRoute],
        endpoint: EndpointInfo,
    ) -> str | None:
        """Connect a public frontend URL through gateway transforms.

        Frontends normally call the gateway path, not the downstream controller
        path. Applying route filters to the concrete client path preserves that
        important edge instead of incorrectly marking the endpoint as uncalled.
        """
        concrete_call = re.sub(r"\{[^}]+\}", "value", call.path)
        for route in routes:
            if route.methods and call.method not in route.methods:
                continue
            if not any(
                re.fullmatch(self._path_regex(pattern), concrete_call)
                for pattern in route.path_patterns
            ):
                continue
            downstream = self._apply_gateway_filters(call.path, route.filters)
            if self._endpoint_match(downstream, endpoint.path):
                return "gateway_transform"
        return None

    @staticmethod
    def _link_record(
        source_kind: str,
        source_id: str,
        endpoint: EndpointInfo,
        match_kind: str,
        confidence: float,
    ) -> AttackSurfaceLink:
        return AttackSurfaceLink(
            source_kind=source_kind,
            source_id=source_id,
            endpoint_path=endpoint.path,
            endpoint_method=endpoint.method,
            endpoint_file_path=endpoint.file_path,
            endpoint_repository_id=endpoint.repository_id,
            match_kind=match_kind,
            confidence=confidence,
        )

    @staticmethod
    def _method_matches(client_method: str, endpoint_method: str) -> bool:
        endpoint_methods = {m.strip() for m in endpoint_method.split(",")}
        return "ALL" in endpoint_methods or client_method in endpoint_methods

    def _endpoint_match(self, client_path: str, endpoint_path: str) -> str | None:
        if client_path.rstrip("/") == endpoint_path.rstrip("/"):
            return "exact"
        if self._canonical_path(client_path) == self._canonical_path(endpoint_path):
            return "template"
        concrete_client = re.sub(r"\{[^}]+\}", "value", client_path)
        if re.fullmatch(self._path_regex(endpoint_path), concrete_client):
            return "template"
        return None

    def _gateway_match(self, route: GatewayRoute, endpoint_path: str) -> str | None:
        for public_pattern in route.path_patterns:
            if re.fullmatch(self._path_regex(public_pattern), endpoint_path):
                return "gateway_pattern"
            downstream = self._apply_gateway_filters(public_pattern, route.filters)
            if downstream != public_pattern and re.fullmatch(
                self._path_regex(downstream), endpoint_path
            ):
                return "gateway_transform"
        return None

    @staticmethod
    def _apply_gateway_filters(path: str, filters: list[str]) -> str:
        result = path
        for filter_text in filters:
            name, separator, raw_args = str(filter_text).partition("=")
            if not separator:
                continue
            name = name.strip().lower()
            args = raw_args.strip()
            if name == "stripprefix" and args.isdigit():
                count = int(args)
                segments = result.lstrip("/").split("/")
                result = "/" + "/".join(segments[count:])
            elif name == "prefixpath":
                prefix = AttackSurfaceAnalyzer._strip_filter_literal(args)
                result = f"/{prefix.strip('/')}/{result.lstrip('/')}"
            elif name == "setpath":
                result = AttackSurfaceAnalyzer._strip_filter_literal(args)
            elif name == "rewritepath":
                parts = args.split(",", 1)
                if len(parts) != 2:
                    continue
                pattern = AttackSurfaceAnalyzer._strip_filter_literal(parts[0])
                replacement = AttackSurfaceAnalyzer._strip_filter_literal(parts[1])
                pattern = re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", pattern)
                replacement = re.sub(r"\$\{([A-Za-z_]\w*)\}", r"\\g<\1>", replacement)
                try:
                    result = re.sub(pattern, replacement, result)
                except re.error:
                    continue
            result = re.sub(r"/{2,}", "/", result)
        return result

    @staticmethod
    def _strip_filter_literal(value: str) -> str:
        return value.strip().strip("'\"").strip()

    @staticmethod
    def _canonical_path(path: str) -> str:
        value = re.sub(r"\{[^}]+\}|<[^>]+>|:[A-Za-z_][\w]*", "{}", path)
        return value.rstrip("/") or "/"

    @staticmethod
    def _path_regex(path: str) -> str:
        token = "__AEGIFY_PARAM__"
        many = "__AEGIFY_MANY__"
        one = "__AEGIFY_ONE__"
        value = re.sub(r"\{[^}]+\}|<[^>]+>|:[A-Za-z_][\w]*", token, path)
        value = value.replace("**", many).replace("*", one)
        escaped = re.escape(value.rstrip("/") or "/")
        escaped = escaped.replace(token, "[^/]+")
        escaped = escaped.replace(many, ".*").replace(one, "[^/]*")
        return escaped + "/?"
