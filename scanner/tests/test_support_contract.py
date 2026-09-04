"""Executable language and endpoint coverage contract."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegify.config import AegifyConfig
from aegify.models import Language
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.call_graph import (
    HEURISTIC_CALL_GRAPH_LANGUAGES,
    CallGraphBuilder,
)
from aegify.scanner.endpoint_detector import ENDPOINT_SUPPORT_MATRIX, EndpointDetector
from aegify.scanner.engine import ScanEngine

CALL_GRAPH_CASES = [
    (
        Language.PYTHON,
        "graph.py",
        "def helper():\n    pass\n\ndef entry():\n    helper()\n",
        "entry",
        "helper",
    ),
    (
        Language.JAVASCRIPT,
        "graph.js",
        "function helper() {}\nfunction entry() { helper(); }\n",
        "entry",
        "helper",
    ),
    (
        Language.TYPESCRIPT,
        "graph.ts",
        "function helper(): void {}\nfunction entry(): void { helper(); }\n",
        "entry",
        "helper",
    ),
    (
        Language.JAVA,
        "Graph.java",
        "class Graph {\n  void helper() {}\n  void entry() {\n    helper();\n  }\n}\n",
        "Graph.entry",
        "Graph.helper",
    ),
    (
        Language.GO,
        "graph.go",
        "package graph\nfunc helper() {}\nfunc entry() { helper() }\n",
        "entry",
        "helper",
    ),
    (
        Language.RUST,
        "graph.rs",
        "fn helper() {}\nfn entry() { helper(); }\n",
        "entry",
        "helper",
    ),
    (
        Language.SWIFT,
        "graph.swift",
        "func helper() {}\nfunc entry() { helper() }\n",
        "entry",
        "helper",
    ),
    (
        Language.KOTLIN,
        "graph.kt",
        "fun helper() {}\nfun entry() { helper() }\n",
        "entry",
        "helper",
    ),
]


@pytest.mark.parametrize(
    ("language", "filename", "source", "caller", "callee"),
    CALL_GRAPH_CASES,
    ids=[case[0].value for case in CALL_GRAPH_CASES],
)
def test_call_graph_contract_resolves_every_supported_language(
    tmp_path: Path,
    language: Language,
    filename: str,
    source: str,
    caller: str,
    callee: str,
) -> None:
    path = tmp_path / filename
    path.write_text(source)
    ast = ASTParser().parse_file(path)
    assert ast is not None
    assert ast.language == language

    builder = CallGraphBuilder()
    builder.build([ast])

    assert callee in builder.get_callees(caller)


def test_call_graph_support_contract_covers_parser_registry() -> None:
    assert HEURISTIC_CALL_GRAPH_LANGUAGES == frozenset(Language)


def test_typescript_relative_import_resolves_without_global_name_guessing(
    tmp_path: Path,
) -> None:
    service = tmp_path / "service.ts"
    service.write_text("export function helper(): void {}\n")
    route = tmp_path / "route.ts"
    route.write_text(
        'import { helper } from "./service";\nexport function entry(): void { helper(); }\n'
    )
    parser = ASTParser()
    asts = [parser.parse_file(service), parser.parse_file(route)]

    builder = CallGraphBuilder()
    builder.build([ast for ast in asts if ast is not None])

    assert "helper" in builder.get_callees("entry")
    assert (str(route), "helper") in builder._import_map


def test_typescript_aliased_relative_import_preserves_local_binding(tmp_path: Path) -> None:
    service = tmp_path / "service.ts"
    service.write_text("export function helper(): void {}\n")
    route = tmp_path / "route.ts"
    route.write_text(
        'import { helper as invokeHelper } from "./service";\n'
        "export function entry(): void { invokeHelper(); }\n"
    )
    parser = ASTParser()
    asts = [parser.parse_file(service), parser.parse_file(route)]

    builder = CallGraphBuilder()
    builder.build([ast for ast in asts if ast is not None])

    assert "helper" in builder.get_callees("entry")
    assert (str(route), "invokeHelper") in builder._import_map


CROSS_FILE_CASES = [
    (
        Language.PYTHON,
        "service.py",
        "def helper():\n    pass\n",
        "entry.py",
        "from service import helper as invoke\ndef entry():\n    invoke()\n",
        "entry",
        "helper",
    ),
    (
        Language.JAVASCRIPT,
        "service.js",
        "export function helper() {}\n",
        "entry.js",
        'import { helper } from "./service";\nexport function entry() { helper(); }\n',
        "entry",
        "helper",
    ),
    (
        Language.TYPESCRIPT,
        "service.ts",
        "export function helper(): void {}\n",
        "entry.ts",
        'import { helper } from "./service";\nexport function entry(): void { helper(); }\n',
        "entry",
        "helper",
    ),
    (
        Language.JAVA,
        "local/Helper.java",
        "package local; public class Helper { public static void run() {} }\n",
        "Entry.java",
        "import local.Helper; class Entry { void entry() { Helper.run(); } }\n",
        "Entry.entry",
        "Helper.run",
    ),
    (
        Language.GO,
        "service/helper.go",
        "package service\nfunc Helper() {}\n",
        "entry.go",
        'package main\nimport "example/service"\nfunc entry() { service.Helper() }\n',
        "entry",
        "Helper",
    ),
    (
        Language.RUST,
        "service.rs",
        "pub fn helper() {}\n",
        "main.rs",
        "mod service;\nuse crate::service::helper;\nfn entry() { helper(); }\n",
        "entry",
        "helper",
    ),
    (
        Language.SWIFT,
        "Service.swift",
        "func helper() {}\n",
        "Entry.swift",
        "func entry() { helper() }\n",
        "entry",
        "helper",
    ),
    (
        Language.KOTLIN,
        "local/Helper.kt",
        "package local\nfun helper() {}\n",
        "Entry.kt",
        "import local.helper\nfun entry() { helper() }\n",
        "entry",
        "helper",
    ),
]


@pytest.mark.parametrize(
    (
        "language",
        "target_name",
        "target_source",
        "caller_name",
        "caller_source",
        "caller",
        "callee",
    ),
    CROSS_FILE_CASES,
    ids=[case[0].value for case in CROSS_FILE_CASES],
)
def test_repository_scoped_cross_file_contract(
    tmp_path: Path,
    language: Language,
    target_name: str,
    target_source: str,
    caller_name: str,
    caller_source: str,
    caller: str,
    callee: str,
) -> None:
    target = tmp_path / target_name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(target_source)
    caller_path = tmp_path / caller_name
    caller_path.write_text(caller_source)
    parser = ASTParser()
    asts = [
        parser.parse_file(target, repository_id="contract", repository_root=tmp_path),
        parser.parse_file(caller_path, repository_id="contract", repository_root=tmp_path),
    ]

    builder = CallGraphBuilder()
    builder.build([ast for ast in asts if ast is not None])

    assert callee in builder.get_callees(caller)


def test_same_named_route_handlers_remain_file_scoped_entry_candidates(
    tmp_path: Path,
) -> None:
    paths = [
        tmp_path / "app" / "api" / "alpha" / "route.ts",
        tmp_path / "app" / "api" / "beta" / "route.ts",
    ]
    parser = ASTParser()
    asts = []
    for index, path in enumerate(paths):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"function helper{index}(): void {{}}\n"
            f"export function GET(): void {{ helper{index}(); }}\n"
        )
        ast = parser.parse_file(path)
        assert ast is not None
        asts.append(ast)

    builder = CallGraphBuilder()
    graph = builder.build(asts)
    route_nodes = [
        node
        for node, attributes in graph.nodes(data=True)
        if attributes["data"].qualified_name == "GET"
    ]
    endpoints = EndpointDetector().detect(asts)

    assert len(route_nodes) == 2
    assert len(set(route_nodes)) == 2
    assert {graph.nodes[node]["data"].file_path for node in route_nodes} == {
        str(path) for path in paths
    }
    assert all(graph.out_degree(node) == 1 for node in route_nodes)
    assert {(endpoint.path, endpoint.handler_function) for endpoint in endpoints} == {
        ("/api/alpha", "GET"),
        ("/api/beta", "GET"),
    }


def test_scan_engine_links_every_same_named_next_handler(tmp_path: Path) -> None:
    for route_name in ("alpha", "beta"):
        path = tmp_path / "app" / "api" / route_name / "route.ts"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("export function GET(): Response { return new Response(); }\n")
    config = AegifyConfig()
    config.llm.enabled = False
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan(tmp_path)
    entry_files = {
        attributes["data"].file_path
        for _, attributes in engine._last_call_graph.nodes(data=True)
        if attributes.get("data") and attributes["data"].is_entry_point
    }

    assert {(endpoint.path, endpoint.handler_function) for endpoint in result.endpoints} == {
        ("/api/alpha", "GET"),
        ("/api/beta", "GET"),
    }
    assert entry_files == {
        str(tmp_path / "app" / "api" / "alpha" / "route.ts"),
        str(tmp_path / "app" / "api" / "beta" / "route.ts"),
    }
    assert {
        "file:app/api/alpha/route.ts::GET()",
        "file:app/api/beta/route.ts::GET()",
    } <= set(engine._last_program_graph)


def test_scan_engine_detects_next_app_root_route(tmp_path: Path) -> None:
    path = tmp_path / "app" / "route.ts"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("export function GET(): Response { return new Response(); }\n")

    config = AegifyConfig()
    config.llm.enabled = False
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan(tmp_path)

    assert {(endpoint.path, endpoint.handler_function) for endpoint in result.endpoints} == {
        ("/", "GET"),
    }


ENDPOINT_CASES = [
    (
        Language.PYTHON,
        "Flask",
        "flask_routes.py",
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.get("/flask/items")\n'
        "def items():\n    pass\n",
        "/flask/items",
        "GET",
    ),
    (
        Language.PYTHON,
        "FastAPI",
        "fastapi_routes.py",
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        '@app.post("/fastapi/items")\n'
        "def items():\n    pass\n",
        "/fastapi/items",
        "POST",
    ),
    (
        Language.PYTHON,
        "Django",
        "django_urls.py",
        "from django.urls import path\n"
        "def items(request):\n    pass\n"
        'urlpatterns = [path("django/items/", items)]\n',
        "/django/items/",
        "ALL",
    ),
    (
        Language.JAVASCRIPT,
        "Express",
        "express_routes.js",
        'function items(req, res) {}\napp.get("/express/items", items);\n',
        "/express/items",
        "GET",
    ),
    (
        Language.TYPESCRIPT,
        "Express",
        "express_routes.ts",
        "function items(req: unknown, res: unknown): void {}\n"
        'app.patch("/express-ts/items", items);\n',
        "/express-ts/items",
        "PATCH",
    ),
    (
        Language.TYPESCRIPT,
        "NestJS",
        "nest_routes.ts",
        '@Controller("nest")\nexport class ItemsController {\n  @Get("items")\n  items() {}\n}\n',
        "/nest/items",
        "GET",
    ),
    (
        Language.TYPESCRIPT,
        "Next.js App Router",
        "app/api/next-items/route.ts",
        "export async function POST(request: Request) { return new Response(); }\n",
        "/api/next-items",
        "POST",
    ),
    (
        Language.JAVA,
        "Spring",
        "SpringRoutes.java",
        '@RequestMapping("/spring") class SpringRoutes {\n'
        '  @GetMapping("/items") Object items() { return null; }\n}\n',
        "/spring/items",
        "GET",
    ),
    (
        Language.GO,
        "Go net/http",
        "nethttp_routes.go",
        "package routes\n"
        "func items(w any, r any) {}\n"
        'func setup() { http.HandleFunc("/go/items", items) }\n',
        "/go/items",
        "ALL",
    ),
    (
        Language.GO,
        "Gin",
        "gin_routes.go",
        "package routes\n"
        'import "github.com/gin-gonic/gin"\n'
        "func items(c any) {}\n"
        'func setup() { router.GET("/gin/items", items) }\n',
        "/gin/items",
        "GET",
    ),
    (
        Language.GO,
        "Echo",
        "echo_routes.go",
        "package routes\n"
        'import "github.com/labstack/echo/v4"\n'
        "func items(c any) {}\n"
        'func setup() { router.POST("/echo/items", items) }\n',
        "/echo/items",
        "POST",
    ),
    (
        Language.GO,
        "Fiber",
        "fiber_routes.go",
        "package routes\n"
        'import "github.com/gofiber/fiber/v3"\n'
        "func items(c any) {}\n"
        'func setup() { app.PUT("/fiber/items", items) }\n',
        "/fiber/items",
        "PUT",
    ),
    (
        Language.GO,
        "Chi",
        "chi_routes.go",
        "package routes\n"
        'import "github.com/go-chi/chi/v5"\n'
        "func items(w any, r any) {}\n"
        'func setup() { router.Get("/chi/items", items) }\n',
        "/chi/items",
        "GET",
    ),
    (
        Language.GO,
        "Gorilla",
        "gorilla_routes.go",
        "package routes\n"
        "func items(w any, r any) {}\n"
        'func setup() { router.HandleFunc("/gorilla/items", items).Methods("DELETE") }\n',
        "/gorilla/items",
        "DELETE",
    ),
    (
        Language.RUST,
        "Actix Web",
        "actix_routes.rs",
        'use actix_web::get;\n#[get("/actix/items")]\nasync fn items() {}\n',
        "/actix/items",
        "GET",
    ),
    (
        Language.RUST,
        "Axum",
        "axum_routes.rs",
        'async fn items() {}\nfn routes() { Router::new().route("/axum/items", post(items)); }\n',
        "/axum/items",
        "POST",
    ),
    (
        Language.RUST,
        "Rocket",
        "rocket_routes.rs",
        'use rocket::get;\n#[get("/rocket/items")]\nfn items() {}\n',
        "/rocket/items",
        "GET",
    ),
    (
        Language.SWIFT,
        "Vapor",
        "vapor_routes.swift",
        "import Vapor\n"
        "func items(_ req: Request) {}\n"
        'func routes(_ app: Application) { app.get("vapor", "items", use: items) }\n',
        "/vapor/items",
        "GET",
    ),
    (
        Language.SWIFT,
        "Hummingbird",
        "hummingbird_routes.swift",
        "import Hummingbird\n"
        "func items(_ request: Request) {}\n"
        "func routes(_ router: Router) { "
        'router.patch("/hummingbird/items", use: items) }\n',
        "/hummingbird/items",
        "PATCH",
    ),
    (
        Language.KOTLIN,
        "Spring",
        "SpringRoutes.kt",
        '@RequestMapping("/kotlin") class SpringRoutes {\n'
        '  @DeleteMapping("/items") fun items() {}\n}\n',
        "/kotlin/items",
        "DELETE",
    ),
    (
        Language.KOTLIN,
        "Ktor",
        "ktor_routes.kt",
        'fun routes() { routing { get("/ktor/items") { call.respond("ok") } } }\n',
        "/ktor/items",
        "GET",
    ),
]


@pytest.mark.parametrize(
    ("language", "framework", "relative_path", "source", "path", "method"),
    ENDPOINT_CASES,
    ids=[f"{case[0].value}-{case[1]}" for case in ENDPOINT_CASES],
)
def test_endpoint_framework_contract(
    tmp_path: Path,
    language: Language,
    framework: str,
    relative_path: str,
    source: str,
    path: str,
    method: str,
) -> None:
    source_path = tmp_path / relative_path
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(source)
    ast = ASTParser().parse_file(source_path)
    assert ast is not None
    assert ast.language == language

    endpoints = EndpointDetector().detect([ast])

    matches = [
        endpoint
        for endpoint in endpoints
        if endpoint.path == path and endpoint.method == method and endpoint.framework == framework
    ]
    assert matches, endpoints
    assert not matches[0].handler_function.startswith("<module:")


def test_endpoint_support_contract_covers_every_parser_language() -> None:
    assert set(ENDPOINT_SUPPORT_MATRIX) == set(Language)
    exercised = {(language, framework) for language, framework, *_ in ENDPOINT_CASES}
    declared = {
        (language, framework)
        for language, frameworks in ENDPOINT_SUPPORT_MATRIX.items()
        for framework in frameworks
    }
    assert declared <= exercised


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        (
            "plain.py",
            "class Store:\n    def get(self, path):\n        pass\n"
            '@app.get("/fake")\ndef value():\n    pass\n',
        ),
        ("plain.go", 'package plain\nfunc setup() { db.Get("/fake", handler) }\n'),
        ("plain.rs", '#[get("/fake")]\nfn value() {}\n'),
        ("plain.swift", 'func setup() { app.get("/fake", use: value) }\n'),
    ],
)
def test_framework_shaped_code_without_framework_evidence_is_not_an_endpoint(
    tmp_path: Path,
    filename: str,
    source: str,
) -> None:
    source_path = tmp_path / filename
    source_path.write_text(source)
    ast = ASTParser().parse_file(source_path)
    assert ast is not None

    assert EndpointDetector().detect([ast]) == []


def test_flask_multi_method_registration_expands_to_distinct_endpoints(tmp_path: Path) -> None:
    source_path = tmp_path / "flask_multi.py"
    source_path.write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.route("/items", methods=["GET", "POST"])\n'
        "def items():\n    pass\n"
    )
    ast = ASTParser().parse_file(source_path)
    assert ast is not None

    endpoints = EndpointDetector().detect([ast])

    assert {(endpoint.path, endpoint.method) for endpoint in endpoints} == {
        ("/items", "GET"),
        ("/items", "POST"),
    }


def test_next_production_route_with_test_prefixed_segment_is_not_filtered(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "app" / "api" / "settings" / "test-llm" / "route.ts"
    source_path.parent.mkdir(parents=True)
    source_path.write_text("export function POST(): Response { return new Response(); }\n")
    ast = ASTParser().parse_file(source_path)
    assert ast is not None

    endpoints = EndpointDetector().detect([ast])

    assert [(endpoint.path, endpoint.method) for endpoint in endpoints] == [
        ("/api/settings/test-llm", "POST")
    ]


def test_test_prefixed_source_filename_is_still_filtered(tmp_path: Path) -> None:
    source_path = tmp_path / "test_routes.py"
    source_path.write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.get("/should-not-ship")\n'
        "def route():\n    pass\n"
    )
    ast = ASTParser().parse_file(source_path)
    assert ast is not None

    assert EndpointDetector().detect([ast]) == []
