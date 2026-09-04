"""Endpoint detector inspired by OWASP Noir.

Scans ASTs for framework-specific route/endpoint patterns to map the
application's attack surface.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field, replace

from aegify.models import FileAST, FunctionDef, Language

logger = logging.getLogger(__name__)


# The endpoint detector's tested support contract.  "100% endpoint language
# coverage" means every parser-supported language has at least one declared
# framework family and a parser-backed regression fixture.  It does not claim
# to discover arbitrary dynamic registrations or every third-party framework.
ENDPOINT_SUPPORT_MATRIX: dict[Language, tuple[str, ...]] = {
    Language.PYTHON: ("Flask", "FastAPI", "Django"),
    Language.JAVASCRIPT: ("Express",),
    Language.TYPESCRIPT: ("Express", "NestJS", "Next.js App Router"),
    Language.JAVA: ("Spring",),
    Language.GO: ("Go net/http", "Gin", "Echo", "Fiber", "Chi", "Gorilla"),
    Language.RUST: ("Actix Web", "Axum", "Rocket"),
    Language.SWIFT: ("Vapor", "Hummingbird"),
    Language.KOTLIN: ("Spring", "Ktor"),
}


@dataclass
class EndpointParam:
    """A parameter accepted by an endpoint."""

    name: str
    location: str = "unknown"  # path, query, body, header
    param_type: str = ""


@dataclass
class Endpoint:
    """A detected API endpoint."""

    path: str
    method: str  # GET, POST, PUT, DELETE, PATCH, ALL
    handler_function: str
    file_path: str
    line_start: int
    line_end: int
    framework: str = ""
    auth_required: bool = False
    parameters: list[EndpointParam] = field(default_factory=list)
    middleware: list[str] = field(default_factory=list)
    repository_id: str = ""


# --- Framework pattern definitions ---

# Flask / FastAPI: @app.route('/path', methods=['GET']) or @app.get('/path')
_FLASK_ROUTE_RE = re.compile(
    r"@\w+\.route\(\s*['\"]([^'\"]+)['\"]"
    r"([^)]*)\)"
)
_FLASK_METHOD_RE = re.compile(
    r"@\w+\.(get|post|put|delete|patch|head|options)\(\s*['\"]([^'\"]+)['\"]"
)

# FastAPI - same decorator style as Flask method shortcuts
_FASTAPI_METHOD_RE = _FLASK_METHOD_RE

# Django: path('url/', view) and @api_view(['GET'])
_DJANGO_PATH_RE = re.compile(r"(?:re_)?path\(\s*['\"]([^'\"]+)['\"]\s*,\s*([\w.]+)")
_DJANGO_API_VIEW_RE = re.compile(r"@api_view\(\s*\[([^\]]+)\]\s*\)")

# Express.js: app.get('/path', handler) or router.post('/path', ...)
_EXPRESS_RE = re.compile(
    r"(?:app|router)\.(get|post|put|delete|patch|head|options|all)"
    r"\(\s*['\"]([^'\"]+)['\"]"
)

# NestJS decorators. Controller paths are joined with method decorators.
_NEST_CONTROLLER_RE = re.compile(
    r"@Controller\(\s*['\"]([^'\"]*)['\"]\s*\)\s*"
    r"(?:export\s+)?class\s+([A-Za-z_$][\w$]*)",
    re.MULTILINE,
)
_NEST_METHOD_RE = re.compile(
    r"@(Get|Post|Put|Delete|Patch|Options|Head|All)\(\s*"
    r"(?:['\"]([^'\"]*)['\"])?\s*\)"
)

# Next.js App Router handlers are exported HTTP-method functions in
# app/**/route.{js,ts}. The URL is derived from the file path.
_NEXT_HANDLER_RE = re.compile(
    r"\bexport\s+(?:async\s+)?function\s+"
    r"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s*\("
)

# Spring: @GetMapping("/path"), @PostMapping, @RequestMapping
_SPRING_RE = re.compile(
    r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*"
    r"(?:(?:value|path)\s*=\s*)?(?:arrayOf\s*\(\s*|\{\s*)?"
    r"['\"]([^'\"]+)['\"]"
)
_SPRING_METHOD_MAP = {
    "Get": "GET",
    "Post": "POST",
    "Put": "PUT",
    "Delete": "DELETE",
    "Patch": "PATCH",
    "Request": "ALL",
}

# Go net/http: http.HandleFunc("/path", handler)
_GO_HANDLE_RE = re.compile(
    r"(?:http\.HandleFunc|mux\.HandleFunc|http\.Handle)"
    r"\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_]\w*)"
)
_GO_ROUTER_RE = re.compile(
    r"\b([A-Za-z_]\w*)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|Any|"
    r"Get|Post|Put|Delete|Patch|Options|Head)"
    r"\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_]\w*)"
)
_GO_METHOD_FUNC_RE = re.compile(
    r"\b([A-Za-z_]\w*)\.MethodFunc\(\s*['\"]([A-Z]+)['\"]\s*,\s*"
    r"['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_]\w*)"
)
_GO_GORILLA_METHODS_RE = re.compile(
    r"\b([A-Za-z_]\w*)\.HandleFunc\(\s*['\"]([^'\"]+)['\"]\s*,\s*"
    r"([A-Za-z_]\w*)\s*\)\.Methods\(\s*['\"]([A-Z]+)['\"]"
)

# Ktor (Kotlin): get("/path") { ... }, post("/path") { ... }
# Require path to start with / to avoid matching Map.get("key"), JSONObject.put("field") etc.
_KTOR_RE = re.compile(r"\b(get|post|put|delete|patch|head|options)\(\s*\"(/[^\"]*)\"")

# Rust: Actix/Rocket route attributes and Axum Router::route calls.
_RUST_ATTRIBUTE_ROUTE_RE = re.compile(
    r"#\[(get|post|put|delete|patch|head|options)\(\s*['\"]([^'\"]+)['\"]\s*\)\]"
)
_RUST_AXUM_RE = re.compile(
    r"\.route\(\s*['\"]([^'\"]+)['\"]\s*,\s*"
    r"(get|post|put|delete|patch|head|options)\(\s*([A-Za-z_]\w*)"
)

# Swift: Vapor and Hummingbird registrations. Both accept either a slash path
# or comma-separated string components such as "users", ":id".
_SWIFT_ROUTE_RE = re.compile(
    r"\b(app|router)\.(get|post|put|delete|patch|head|options)\("
    r"(?P<arguments>[^\n)]*)\)"
)

# Auth decorator patterns
_AUTH_PATTERNS = [
    # Python / Django / Flask
    "login_required",
    "auth_required",
    "requires_auth",
    "permission_required",
    "permissions_required",
    "IsAuthenticated",
    "IsAdminUser",
    "IsAuthenticatedOrReadOnly",
    "has_permission",
    "check_permission",
    # FastAPI
    "Depends(get_current_user",
    "Depends(verify_token",
    "Depends(require_auth",
    "Security(",
    # Flask-JWT / Flask-Login
    "jwt_required",
    "token_required",
    "fresh_jwt_required",
    "verify_jwt_in_request",
    # Spring
    "@PreAuthorize",
    "@Secured",
    "@RolesAllowed",
    "hasRole",
    "hasAuthority",
    "isAuthenticated",
    # Express.js
    "passport.authenticate",
    "ensureAuthenticated",
    "requireAuth",
    "verifyToken",
    "authMiddleware",
    "authenticate",
    "requireLogin",
    "checkAuth",
    "jwt(",
    "expressjwt",
    # NestJS
    "@UseGuards(AuthGuard",
    "@UseGuards(JwtAuthGuard",
    "AuthGuard",
    "JwtAuthGuard",
    "RolesGuard",
    # Go
    "AuthMiddleware",
    "RequireAuth",
    "JWTMiddleware",
    # General
    "Authorize",
    "bearer",
    "api_key",
    "apiKey",
    "OAuth2",
    "oauth2",
]


# Test directory patterns — endpoints from test files are noise
_TEST_PATH_SEGMENTS = {
    "/test/",
    "/tests/",
    "/Test/",
    "/__tests__/",
    "/spec/",
    "/specs/",
    "/testFixtures/",
    "/testdata/",
    "/testing/",
    "/src/test/",
    "/src/androidTest/",
}
_TEST_FILE_SUFFIXES = (
    "Test.kt",
    "Test.java",
    "Test.py",
    "Test.ts",
    "Test.js",
    "Tests.kt",
    "Tests.java",
    "Tests.py",
    ".test.ts",
    ".test.js",
    ".test.tsx",
    ".test.jsx",
    ".spec.ts",
    ".spec.js",
    ".spec.tsx",
    ".spec.jsx",
    "_test.py",
    "_test.go",
)

# Endpoint quality filter patterns
_STATIC_PATH_PATTERNS = [
    "/static/",
    "/public/",
    "/assets/",
    "/css/",
    "/js/",
    "/images/",
    "/fonts/",
    "/media/",
    "/uploads/",
    "/dist/",
    "/build/",
    "/vendor/",
    "/node_modules/",
    "/.git/",
    "/.next/",
    "/bower_components/",
]
_FILE_EXTENSIONS = [
    ".html",
    ".css",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".md",
    ".txt",
    ".csv",
    ".log",
]
_INTERNAL_PREFIXES = [
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/alive",
    "/status",
    "/ping",
    "/metrics",
    "/prometheus",
    "/actuator",
    "/__",
    "/_internal",
    "/_debug",
    "/_next/",
    "/_nuxt/",
    "/.well-known/",
]
_WILDCARD_SUFFIXES = [
    "/*",
    "/**",
    "/*path",
    "/{*path}",
    "/<path:path>",
    "/:splat*",
    "/(.*)",
    "/{path:.*}",
    "/{**}",
]
# Regex for paths that are just a single path parameter: /{id}, /:id, <int:id>
_PARAM_ONLY_ROOT_RE = re.compile(r"^/[{<:][\w:.>}]+$")


class EndpointDetector:
    """Detects API endpoints from parsed ASTs using framework-specific patterns."""

    def detect(self, file_asts: list[FileAST]) -> list[Endpoint]:
        """Detect all endpoints across the given file ASTs.

        Deduplication strategy:
        1. File-level dedup: (path, method, file_path) to avoid duplicates from
           overlapping decorator + source pattern detection within a single file.
        2. Global dedup: (path, method) to ensure each API path is unique per
           HTTP method. When duplicates exist across files, keeps the one with
           more metadata (auth_required, parameters, framework info).
        """
        endpoints: list[Endpoint] = []

        for ast in file_asts:
            # Skip test files — endpoints from tests are noise (test HTTP clients, mock routes)
            if self._is_test_file(ast.file_path):
                continue
            endpoints.extend(self._detect_from_decorators(ast))
            endpoints.extend(self._detect_from_source_patterns(ast))

        # Phase 1: File-level dedup by (path, method, file)
        file_seen: set[tuple[str, str, str]] = set()
        file_unique: list[Endpoint] = []
        for ep in endpoints:
            file_key = (ep.path, ep.method, ep.file_path)
            if file_key not in file_seen:
                file_seen.add(file_key)
                file_unique.append(ep)

        # Phase 2: Repository-aware dedup. Identical routes in separate services
        # are distinct attack-surface nodes in a multi-repository workspace.
        global_best: dict[tuple[str, str, str], Endpoint] = {}
        for ep in file_unique:
            endpoint_key = (ep.repository_id, ep.path, ep.method)
            existing = global_best.get(endpoint_key)
            if existing is None:
                global_best[endpoint_key] = ep
            else:
                # Keep the one with more metadata
                new_score = self._endpoint_richness(ep)
                old_score = self._endpoint_richness(existing)
                if new_score > old_score:
                    global_best[endpoint_key] = ep

        unique = list(global_best.values())

        # Phase 3: Filter out non-API endpoints
        api_endpoints = [ep for ep in unique if self._is_api_endpoint(ep)]
        filtered_count = len(unique) - len(api_endpoints)
        if filtered_count > 0:
            logger.info(
                "Filtered %d non-API endpoints (static, wildcard, internal)",
                filtered_count,
            )

        # Phase 4: Resolve Spring Security config-based auth
        security_rules = self._parse_spring_security_configs(file_asts)
        if security_rules:
            resolved = self._apply_security_rules(api_endpoints, security_rules)
            logger.info(
                "Resolved auth via Spring Security config: %d endpoints marked as auth-required",
                resolved,
            )

        auth_count = sum(1 for ep in api_endpoints if ep.auth_required)
        logger.info(
            "Detected %d endpoints across %d files "
            "(file-level: %d, global-dedup: %d, api-filtered: %d, auth: %d)",
            len(endpoints),
            len(file_asts),
            len(file_unique),
            len(unique),
            len(api_endpoints),
            auth_count,
        )
        return api_endpoints

    @staticmethod
    def _endpoint_richness(ep: Endpoint) -> int:
        """Score an endpoint by how much metadata it has (for dedup preference)."""
        score = 0
        if ep.auth_required:
            score += 2
        if ep.parameters:
            score += len(ep.parameters)
        if ep.framework:
            score += 1
        if ep.middleware:
            score += 1
        if ep.handler_function and not ep.handler_function.startswith("<"):
            score += 1
        return score

    @staticmethod
    def _is_api_endpoint(ep: Endpoint) -> bool:
        """Filter out non-API endpoints (static files, wildcards, health checks)."""
        path = ep.path

        # Must start with / — reject field names, property keys, relative paths
        if not path.startswith("/"):
            return False

        # Reject empty, root, or wildcard-only paths
        if path in ("/", "/*", "/**", "*"):
            return False

        # Reject single-segment parameter-only paths: /{id}, /:id, <int:id>
        # These are too generic without a prefix
        if _PARAM_ONLY_ROOT_RE.match(path):
            return False

        path_lower = path.lower()

        # Reject static asset paths
        if any(p in path_lower for p in _STATIC_PATH_PATTERNS):
            return False

        # Reject file extension endpoints (strip path params first)
        clean = re.sub(r"\{[^}]+\}|<[^>]+>|:[a-zA-Z]+", "", path)
        if any(clean.endswith(ext) for ext in _FILE_EXTENSIONS):
            return False

        # Reject catch-all / wildcard routes
        if any(path.endswith(s) for s in _WILDCARD_SUFFIXES):
            return False

        # Reject internal/monitoring endpoints
        if any(path_lower.startswith(p) for p in _INTERNAL_PREFIXES):
            return False

        # Reject relative file paths
        if path.startswith("./") or path.startswith("../"):
            return False

        return True

    @staticmethod
    def _is_test_file(file_path: str) -> bool:
        """Check if a file is a test file (endpoints from tests are noise)."""
        if any(seg in file_path for seg in _TEST_PATH_SEGMENTS):
            return True
        basename = os.path.basename(file_path).lower()
        if basename.startswith(("test_", "test-")):
            return True
        if file_path.endswith(_TEST_FILE_SUFFIXES):
            return True
        return False

    # --- Spring Security config parsing ---

    # Patterns for security config files
    _SECURITY_CONFIG_NAMES = {
        "securityconfig",
        "securityconfiguration",
        "springsecurityconfig",
        "websecurityconfig",
        "httpsecurityconfig",
    }

    # Regex to extract requestMatchers/antMatchers patterns and their auth decisions
    _MATCHER_RE = re.compile(
        r'\.(requestMatchers|antMatchers)\s*\(\s*"([^"]+)"'
        r'(?:\s*,\s*"([^"]+)")*'  # additional patterns
        r"\s*\)\s*\.\s*(\w+)\s*\(",  # .permitAll(, .authenticated(, .hasRole(, etc.
    )
    _ANY_REQUEST_RE = re.compile(r"\.anyRequest\s*\(\s*\)\s*\.\s*(\w+)\s*\(")

    def _parse_spring_security_configs(self, file_asts: list[FileAST]) -> list[tuple[str, bool]]:
        """Parse Spring Security config files to extract URL auth rules.

        Returns list of (ant_pattern, requires_auth) tuples, ordered by specificity.
        The last entry may be a wildcard ('**') representing anyRequest().
        """
        rules: list[tuple[str, bool]] = []

        # Find security config files
        config_files: list[str] = []
        for ast in file_asts:
            basename = os.path.basename(ast.file_path).lower()
            name_no_ext = basename.rsplit(".", 1)[0] if "." in basename else basename
            if name_no_ext in self._SECURITY_CONFIG_NAMES:
                config_files.append(ast.file_path)

        if not config_files:
            return rules

        for config_path in config_files:
            try:
                with open(config_path) as f:
                    source = f.read()
            except OSError:
                continue

            # Check for authorizeRequests or authorizeHttpRequests
            if "authorizeRequests" not in source and "authorizeHttpRequests" not in source:
                continue

            # Extract requestMatchers/antMatchers rules
            for m in self._MATCHER_RE.finditer(source):
                pattern = m.group(2)
                extra = m.group(3)  # additional pattern if any
                decision = m.group(4)

                is_permit = decision in ("permitAll", "anonymous")
                is_auth = decision in (
                    "authenticated",
                    "hasRole",
                    "hasAuthority",
                    "hasAnyRole",
                    "hasAnyAuthority",
                    "denyAll",
                    "fullyAuthenticated",
                )

                if is_permit:
                    rules.append((pattern, False))
                    if extra:
                        rules.append((extra, False))
                elif is_auth:
                    rules.append((pattern, True))
                    if extra:
                        rules.append((extra, True))

            # Check for anyRequest default
            any_match = self._ANY_REQUEST_RE.search(source)
            if any_match:
                decision = any_match.group(1)
                if decision in ("authenticated", "fullyAuthenticated", "denyAll"):
                    rules.append(("/**", True))
                elif decision == "permitAll":
                    rules.append(("/**", False))

            logger.info("Parsed %d security rules from %s", len(rules), config_path)

        return rules

    @staticmethod
    def _ant_match(pattern: str, path: str) -> bool:
        """Match Spring Ant-style URL pattern against an endpoint path.

        Supports:
        - /** matches everything
        - /admin/** matches /admin/anything/nested
        - /api/*/users matches /api/v1/users
        """
        # Convert Ant pattern to fnmatch-compatible glob
        # /** → everything under prefix
        if pattern.endswith("/**"):
            prefix = pattern[:-3]  # strip /**
            return path == prefix or path.startswith(prefix + "/")
        # /* → single segment wildcard
        if "**" in pattern:
            # General double-star: convert to regex
            regex = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
            return bool(re.fullmatch(regex, path))
        if "*" in pattern:
            regex = re.escape(pattern).replace(r"\*", "[^/]*")
            return bool(re.fullmatch(regex, path))
        # Exact match
        return path == pattern

    def _apply_security_rules(
        self, endpoints: list[Endpoint], rules: list[tuple[str, bool]]
    ) -> int:
        """Apply parsed rules and return the newly auth-marked endpoint count."""
        resolved = 0
        for ep in endpoints:
            if ep.auth_required:
                continue  # Already detected by other means

            # Find the first matching rule (order matters — specific before wildcard)
            matched_auth = None
            for pattern, requires_auth in rules:
                if self._ant_match(pattern, ep.path):
                    matched_auth = requires_auth
                    break  # First match wins (Spring processes in order)

            if matched_auth is True:
                ep.auth_required = True
                resolved += 1

        return resolved

    def _detect_from_decorators(self, ast: FileAST) -> list[Endpoint]:
        """Detect endpoints from function/method decorators."""
        endpoints: list[Endpoint] = []

        spring_prefixes: dict[str, str] = {}
        for cls in ast.classes:
            for decorator in cls.decorators:
                parsed = self._parse_spring_mapping(decorator)
                if parsed:
                    spring_prefixes[cls.name] = parsed[0]
                    break

        all_funcs: list[FunctionDef] = list(ast.functions)
        for cls in ast.classes:
            all_funcs.extend(cls.methods)

        for func in all_funcs:
            for decorator in func.decorators:
                ep = self._parse_decorator(
                    decorator,
                    func,
                    ast.file_path,
                    imported_modules={item.module for item in ast.imports},
                )
                if ep:
                    if ep.framework == "Spring" and func.class_name:
                        ep.path = self._join_paths(
                            spring_prefixes.get(func.class_name, ""), ep.path
                        )
                    # Check for auth decorators
                    ep.auth_required = self._has_auth(func.decorators)
                    if func.class_name:
                        enclosing_class = next(
                            (c for c in ast.classes if c.name == func.class_name),
                            None,
                        )
                        if enclosing_class:
                            ep.auth_required = ep.auth_required or self._has_auth(
                                enclosing_class.decorators
                            )
                    # Extract parameters from path
                    ep.parameters = self._extract_path_params(ep.path)
                    ep.repository_id = ast.repository_id
                    methods = [method for method in ep.method.split(",") if method]
                    endpoints.extend(replace(ep, method=method) for method in methods)

        return endpoints

    def _parse_decorator(
        self,
        decorator: str,
        func: FunctionDef,
        file_path: str,
        *,
        imported_modules: set[str],
    ) -> Endpoint | None:
        """Try to parse a single decorator as an endpoint definition."""
        python_framework = self._python_framework(imported_modules)
        # Flask/FastAPI @app.route
        m = _FLASK_ROUTE_RE.search(decorator)
        if m and python_framework:
            path = m.group(1)
            methods_match = re.search(r"methods\s*=\s*\[([^\]]+)\]", m.group(2))
            methods_str = methods_match.group(1) if methods_match else "'GET'"
            methods = [s.strip().strip("'\"").upper() for s in methods_str.split(",")]
            return Endpoint(
                path=path,
                method=methods[0] if len(methods) == 1 else ",".join(methods),
                handler_function=func.qualified_name,
                file_path=file_path,
                line_start=func.line_start,
                line_end=func.line_end,
                framework=python_framework,
            )

        # Flask/FastAPI @app.get, @app.post etc.
        m = _FLASK_METHOD_RE.search(decorator)
        if m and python_framework:
            method = m.group(1).upper()
            path = m.group(2)
            return Endpoint(
                path=path,
                method=method,
                handler_function=func.qualified_name,
                file_path=file_path,
                line_start=func.line_start,
                line_end=func.line_end,
                framework=python_framework,
            )

        # Django @api_view
        m = _DJANGO_API_VIEW_RE.search(decorator)
        if m:
            methods_str = m.group(1)
            methods = [s.strip().strip("'\"").upper() for s in methods_str.split(",")]
            return Endpoint(
                path=f"/{func.name}/",
                method=methods[0] if len(methods) == 1 else ",".join(methods),
                handler_function=func.qualified_name,
                file_path=file_path,
                line_start=func.line_start,
                line_end=func.line_end,
                framework="Django",
            )

        # Spring annotations
        spring = self._parse_spring_mapping(decorator)
        if spring:
            path, method = spring
            return Endpoint(
                path=path,
                method=method,
                handler_function=func.qualified_name,
                file_path=file_path,
                line_start=func.line_start,
                line_end=func.line_end,
                framework="Spring",
            )

        return None

    @staticmethod
    def _python_framework(imported_modules: set[str]) -> str:
        if any(module == "fastapi" or module.startswith("fastapi.") for module in imported_modules):
            return "FastAPI"
        if any(module == "flask" or module.startswith("flask.") for module in imported_modules):
            return "Flask"
        return ""

    @staticmethod
    def _join_paths(prefix: str, path: str) -> str:
        """Join class-level and method-level route paths without losing root."""
        parts = [p.strip("/") for p in (prefix, path) if p and p != "/"]
        return "/" + "/".join(parts) if parts else "/"

    @staticmethod
    def _parse_spring_mapping(annotation: str) -> tuple[str, str] | None:
        """Parse Java/Kotlin Spring mapping annotations.

        Supports class-level mappings, ``path``/``value`` named arguments,
        Kotlin ``arrayOf`` syntax, and ``RequestMethod`` declarations.
        """
        name_match = re.search(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\b", annotation)
        if not name_match:
            return None
        spring_type = name_match.group(1)
        strings = re.findall(r"['\"]([^'\"]*)['\"]", annotation)
        path = strings[0] if strings else ""
        method = _SPRING_METHOD_MAP.get(spring_type, "ALL")
        if spring_type == "Request":
            method_match = re.search(r"RequestMethod\.([A-Z]+)", annotation)
            if method_match:
                method = method_match.group(1)
        return path, method

    def _detect_from_source_patterns(self, ast: FileAST) -> list[Endpoint]:
        """Detect endpoints from call-site patterns and source-level annotations.

        Restricts pattern matching by file language to prevent cross-language
        false positives (e.g. Django path() matching in Kotlin files).
        """
        endpoints: list[Endpoint] = []

        # Read source file for pattern matching
        try:
            with open(ast.file_path) as f:
                source = f.read()
        except OSError:
            return endpoints

        lines = source.splitlines()

        # The parser is authoritative. Extension re-detection previously made
        # alternate extensions and synthetic/workspace ASTs silently diverge.
        lang = ast.language

        # Express.js patterns — only in JS/TS files
        if lang in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            for m in _EXPRESS_RE.finditer(source):
                method = m.group(1).upper()
                path = m.group(2)
                line_num = source[: m.start()].count("\n") + 1
                # Check for middleware auth in Express route registration line
                route_line = lines[line_num - 1] if line_num <= len(lines) else ""
                has_auth = self._source_has_auth(source, line_num, ast=ast) or any(
                    pat in route_line for pat in _AUTH_PATTERNS
                )
                # Extract middleware names from route args
                middleware: list[str] = []
                route_match = re.search(
                    r"(?:app|router)\.\w+\(\s*['\"][^'\"]+['\"]"
                    r"((?:\s*,\s*\w+)*)"
                    r"\s*,\s*\w+\s*\)",
                    route_line,
                )
                if route_match and route_match.group(1):
                    mw_names = [
                        name.strip().strip(",")
                        for name in route_match.group(1).split(",")
                        if name.strip().strip(",")
                    ]
                    middleware = mw_names
                endpoints.append(
                    Endpoint(
                        path=path,
                        method=method,
                        handler_function=self._registration_handler(
                            ast,
                            line_num,
                            self._last_identifier_argument(source, m.end()),
                        ),
                        file_path=ast.file_path,
                        line_start=line_num,
                        line_end=line_num,
                        framework="Express",
                        parameters=self._extract_path_params(path),
                        auth_required=has_auth,
                        middleware=middleware,
                        repository_id=ast.repository_id,
                    )
                )

            if lang == Language.TYPESCRIPT:
                controller_prefixes = {
                    match.group(2): match.group(1) for match in _NEST_CONTROLLER_RE.finditer(source)
                }
                for m in _NEST_METHOD_RE.finditer(source):
                    method = m.group(1).upper()
                    path = m.group(2) or ""
                    line_num = source[: m.start()].count("\n") + 1
                    handler = self._find_following_func(ast, line_num)
                    class_name = self._function_class(ast, handler)
                    path = self._join_paths(controller_prefixes.get(class_name or "", ""), path)
                    endpoints.append(
                        self._make_endpoint(
                            ast,
                            path=path,
                            method=method,
                            handler=handler,
                            line=line_num,
                            framework="NestJS",
                            source=source,
                        )
                    )

                if self._is_next_route_file(ast.file_path):
                    route_path = self._next_route_path(ast.file_path)
                    for m in _NEXT_HANDLER_RE.finditer(source):
                        line_num = source[: m.start()].count("\n") + 1
                        endpoints.append(
                            self._make_endpoint(
                                ast,
                                path=route_path,
                                method=m.group(1),
                                handler=self._registration_handler(ast, line_num, m.group(1)),
                                line=line_num,
                                framework="Next.js App Router",
                                source=source,
                            )
                        )

        # Go net/http patterns — only in Go files
        if lang == Language.GO:
            for m in _GO_HANDLE_RE.finditer(source):
                path = m.group(1)
                line_num = source[: m.start()].count("\n") + 1
                endpoints.append(
                    self._make_endpoint(
                        ast,
                        path=path,
                        method="ALL",
                        handler=self._registration_handler(ast, line_num, m.group(2)),
                        line=line_num,
                        framework="Go net/http",
                        source=source,
                    )
                )
            for m in _GO_GORILLA_METHODS_RE.finditer(source):
                line_num = source[: m.start()].count("\n") + 1
                endpoints.append(
                    self._make_endpoint(
                        ast,
                        path=m.group(2),
                        method=m.group(4),
                        handler=self._registration_handler(ast, line_num, m.group(3)),
                        line=line_num,
                        framework="Gorilla",
                        source=source,
                    )
                )
            for m in _GO_METHOD_FUNC_RE.finditer(source):
                line_num = source[: m.start()].count("\n") + 1
                endpoints.append(
                    self._make_endpoint(
                        ast,
                        path=m.group(3),
                        method=m.group(2),
                        handler=self._registration_handler(ast, line_num, m.group(4)),
                        line=line_num,
                        framework="Chi",
                        source=source,
                    )
                )
            for m in _GO_ROUTER_RE.finditer(source):
                line_num = source[: m.start()].count("\n") + 1
                method = m.group(2).upper()
                framework = self._go_router_framework(source)
                if not framework:
                    continue
                endpoints.append(
                    self._make_endpoint(
                        ast,
                        path=m.group(3),
                        method="ALL" if method == "ANY" else method,
                        handler=self._registration_handler(ast, line_num, m.group(4)),
                        line=line_num,
                        framework=framework,
                        source=source,
                    )
                )

        # Spring annotation patterns — only in Java/Kotlin files
        if lang in (Language.JAVA, Language.KOTLIN):
            for m in _SPRING_RE.finditer(source):
                spring_type = m.group(1)
                path = m.group(2)
                method = _SPRING_METHOD_MAP.get(spring_type, "ALL")
                line_num = source[: m.start()].count("\n") + 1
                handler = self._find_enclosing_func(ast, line_num)
                # A class-level @RequestMapping is a prefix, not an endpoint.
                if handler.startswith("<module"):
                    continue
                class_prefix = ""
                for cls in ast.classes:
                    if cls.line_start <= line_num <= cls.line_end:
                        for annotation in cls.decorators:
                            parsed = self._parse_spring_mapping(annotation)
                            if parsed:
                                class_prefix = parsed[0]
                                break
                path = self._join_paths(class_prefix, path)
                endpoints.append(
                    Endpoint(
                        path=path,
                        method=method,
                        handler_function=handler,
                        file_path=ast.file_path,
                        line_start=line_num,
                        line_end=line_num,
                        framework="Spring",
                        parameters=self._extract_path_params(path),
                        auth_required=self._source_has_auth(source, line_num, ast=ast),
                        repository_id=ast.repository_id,
                    )
                )

        # Ktor patterns — only in Kotlin files
        if lang == Language.KOTLIN and ("io.ktor" in source or "routing" in source):
            for m in _KTOR_RE.finditer(source):
                method = m.group(1).upper()
                path = m.group(2)
                line_num = source[: m.start()].count("\n") + 1
                endpoints.append(
                    Endpoint(
                        path=path,
                        method=method,
                        handler_function=self._find_enclosing_func(ast, line_num),
                        file_path=ast.file_path,
                        line_start=line_num,
                        line_end=line_num,
                        framework="Ktor",
                        parameters=self._extract_path_params(path),
                        auth_required=self._source_has_auth(source, line_num, ast=ast),
                        repository_id=ast.repository_id,
                    )
                )

        # Django path() patterns — only in Python files
        if lang == Language.PYTHON and "django" in source:
            for m in _DJANGO_PATH_RE.finditer(source):
                path = "/" + m.group(1).lstrip("/")
                line_num = source[: m.start()].count("\n") + 1
                endpoints.append(
                    self._make_endpoint(
                        ast,
                        path=path,
                        method="ALL",
                        handler=self._registration_handler(ast, line_num, m.group(2)),
                        line=line_num,
                        framework="Django",
                        source=source,
                    )
                )

        if lang == Language.RUST:
            framework = ""
            if "actix_web" in source:
                framework = "Actix Web"
            elif re.search(r"(?:use|extern\s+crate)\s+rocket\b", source):
                framework = "Rocket"
            if framework:
                for m in _RUST_ATTRIBUTE_ROUTE_RE.finditer(source):
                    line_num = source[: m.start()].count("\n") + 1
                    endpoints.append(
                        self._make_endpoint(
                            ast,
                            path=m.group(2),
                            method=m.group(1).upper(),
                            handler=self._find_following_func(ast, line_num),
                            line=line_num,
                            framework=framework,
                            source=source,
                        )
                    )
            if "axum" in source or "Router::" in source:
                for m in _RUST_AXUM_RE.finditer(source):
                    line_num = source[: m.start()].count("\n") + 1
                    endpoints.append(
                        self._make_endpoint(
                            ast,
                            path=m.group(1),
                            method=m.group(2).upper(),
                            handler=self._registration_handler(ast, line_num, m.group(3)),
                            line=line_num,
                            framework="Axum",
                            source=source,
                        )
                    )

        if lang == Language.SWIFT and ("import Vapor" in source or "Hummingbird" in source):
            framework = "Hummingbird" if "Hummingbird" in source else "Vapor"
            for m in _SWIFT_ROUTE_RE.finditer(source):
                path = self._swift_route_path(m.group("arguments"))
                if not path:
                    continue
                line_num = source[: m.start()].count("\n") + 1
                handler_match = re.search(r"\buse\s*:\s*([A-Za-z_]\w*)", m.group("arguments"))
                explicit_handler = handler_match.group(1) if handler_match else ""
                endpoints.append(
                    self._make_endpoint(
                        ast,
                        path=path,
                        method=m.group(2).upper(),
                        handler=self._registration_handler(ast, line_num, explicit_handler),
                        line=line_num,
                        framework=framework,
                        source=source,
                    )
                )

        return endpoints

    def _make_endpoint(
        self,
        ast: FileAST,
        *,
        path: str,
        method: str,
        handler: str,
        line: int,
        framework: str,
        source: str,
    ) -> Endpoint:
        return Endpoint(
            path=path,
            method=method,
            handler_function=handler,
            file_path=ast.file_path,
            line_start=line,
            line_end=line,
            framework=framework,
            parameters=self._extract_path_params(path),
            auth_required=self._source_has_auth(source, line, ast=ast),
            repository_id=ast.repository_id,
        )

    @staticmethod
    def _last_identifier_argument(source: str, offset: int) -> str:
        tail = source[offset : offset + 500].split(")", 1)[0]
        identifiers = re.findall(r",\s*([A-Za-z_$][\w$]*)", tail)
        return identifiers[-1] if identifiers else ""

    def _registration_handler(self, ast: FileAST, line: int, name: str) -> str:
        if name:
            candidates = [
                function
                for function in self._all_functions(ast)
                if function.name == name or function.qualified_name == name
            ]
            if len(candidates) == 1:
                return candidates[0].qualified_name
        return self._find_enclosing_func(ast, line)

    def _find_following_func(self, ast: FileAST, line: int) -> str:
        following = [
            function for function in self._all_functions(ast) if function.line_start >= line
        ]
        if following:
            return min(following, key=lambda function: function.line_start).qualified_name
        return self._find_enclosing_func(ast, line)

    @staticmethod
    def _all_functions(ast: FileAST) -> list[FunctionDef]:
        functions = list(ast.functions)
        known = {id(function) for function in functions}
        for cls in ast.classes:
            functions.extend(method for method in cls.methods if id(method) not in known)
        return functions

    def _function_class(self, ast: FileAST, qualified_name: str) -> str | None:
        function = next(
            (item for item in self._all_functions(ast) if item.qualified_name == qualified_name),
            None,
        )
        return function.class_name if function else None

    @staticmethod
    def _go_router_framework(source: str) -> str:
        if "gin-gonic/gin" in source:
            return "Gin"
        if "labstack/echo" in source:
            return "Echo"
        if "gofiber/fiber" in source:
            return "Fiber"
        if "go-chi/chi" in source:
            return "Chi"
        return ""

    @staticmethod
    def _is_next_route_file(file_path: str) -> bool:
        normalized = file_path.replace("\\", "/")
        return bool(re.search(r"(?:^|/)app(?:/.+)?/route\.(?:[jt]sx?)$", normalized))

    @staticmethod
    def _next_route_path(file_path: str) -> str:
        normalized = file_path.replace("\\", "/")
        match = re.search(r"(?:^|/)app(?:/(.+))?/route\.(?:[jt]sx?)$", normalized)
        if not match:
            return "/"
        route_parts = match.group(1) or ""
        if not route_parts:
            return "/"
        parts: list[str] = []
        for part in route_parts.split("/"):
            if part.startswith("(") and part.endswith(")"):
                continue
            if part.startswith("[[...") and part.endswith("]]"):
                parts.append(f":{part[5:-2]}*")
            elif part.startswith("[...") and part.endswith("]"):
                parts.append(f":{part[4:-1]}*")
            elif part.startswith("[") and part.endswith("]"):
                parts.append(f":{part[1:-1]}")
            else:
                parts.append(part)
        return "/" + "/".join(parts)

    @staticmethod
    def _swift_route_path(arguments: str) -> str:
        route_arguments = arguments.split("use:", 1)[0]
        components = re.findall(r"['\"]([^'\"]+)['\"]", route_arguments)
        if not components:
            return ""
        if len(components) == 1 and components[0].startswith("/"):
            return str(components[0])
        return "/" + "/".join(component.strip("/") for component in components)

    def _source_has_auth(self, source: str, line_num: int, *, ast: FileAST | None = None) -> bool:
        """Check if auth annotations exist near the endpoint or at class/file level.

        Checks (in order):
        1. Nearby context (10 lines above the endpoint registration)
        2. Enclosing class decorators/annotations (Spring @PreAuthorize on class)
        3. Ktor authenticate {} block wrapping the route
        4. File-level security middleware imports/setup
        """
        lines = source.splitlines()

        # Check 1: 10 lines above for auth annotations (decorators, middleware args)
        start = max(0, line_num - 11)
        nearby = "\n".join(lines[start:line_num])
        for pattern in _AUTH_PATTERNS:
            if pattern in nearby:
                return True

        # Check 2: Class-level auth annotations (Spring @Secured, @PreAuthorize on class)
        if ast:
            for cls in ast.classes:
                if cls.line_start <= line_num <= cls.line_end:
                    for dec in cls.decorators:
                        for pattern in _AUTH_PATTERNS:
                            if pattern in dec:
                                return True

        # Check 3: Ktor authenticate {} block — scan upward for "authenticate("
        for i in range(max(0, line_num - 2), max(0, line_num - 30), -1):
            line = lines[i] if i < len(lines) else ""
            if "authenticate(" in line or "authenticate {" in line:
                return True

        # Check 4: File-level security setup (Express app.use(passport), Flask-Login, etc.)
        file_auth_patterns = [
            "app.use(passport",
            "app.use(authenticate",
            "app.use(authMiddleware",
            "app.use(requireAuth",
            "app.use(jwt(",
            "app.use(expressjwt",
            "flask_login",
            "Flask-Login",
            "flask_jwt",
            "@login_manager",
            "LoginManager",
            "SecurityFilterChain",
            "WebSecurityConfigurerAdapter",
            "install(Authentication)",
            "install(Sessions)",
        ]
        # Only scan first 50 lines for file-level setup (imports/config)
        file_header = "\n".join(lines[: min(50, len(lines))])
        for pattern in file_auth_patterns:
            if pattern in file_header:
                return True

        return False

    def _find_enclosing_func(self, ast: FileAST, line: int) -> str:
        """Find the function containing the given line."""
        all_funcs = list(ast.functions)
        for cls in ast.classes:
            all_funcs.extend(cls.methods)

        for func in all_funcs:
            if func.line_start <= line <= func.line_end:
                return func.qualified_name

        return f"<module:{ast.file_path}>"

    def _has_auth(self, decorators: list[str]) -> bool:
        """Check if any decorator indicates authentication is required."""
        for dec in decorators:
            for pattern in _AUTH_PATTERNS:
                if pattern in dec:
                    return True
        return False

    def _extract_path_params(self, path: str) -> list[EndpointParam]:
        """Extract path parameters from a route path."""
        params: list[EndpointParam] = []
        # Flask/FastAPI: <param> or {param}
        for m in re.finditer(r"<(?:(\w+):)?(\w+)>|\{(\w+)\}", path):
            name = m.group(2) or m.group(3)
            if name:
                params.append(
                    EndpointParam(name=name, location="path", param_type=m.group(1) or "")
                )
        # Express: :param
        for m in re.finditer(r":(\w+)", path):
            params.append(EndpointParam(name=m.group(1), location="path"))
        return params
