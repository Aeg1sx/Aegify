"""Tests for JVM endpoint and frontend/gateway attack-surface correlation."""

from pathlib import Path

from aegify.models import EndpointInfo, EndpointParam
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.attack_surface import AttackSurfaceAnalyzer
from aegify.scanner.endpoint_detector import EndpointDetector


def _endpoint_info(endpoint):
    return EndpointInfo(
        path=endpoint.path,
        method=endpoint.method,
        handler_function=endpoint.handler_function,
        file_path=endpoint.file_path,
        line_start=endpoint.line_start,
        line_end=endpoint.line_end,
        framework=endpoint.framework,
        auth_required=endpoint.auth_required,
        parameters=[
            EndpointParam(name=p.name, location=p.location, param_type=p.param_type)
            for p in endpoint.parameters
        ],
        repository_id=endpoint.repository_id,
    )


def test_spring_class_prefix_and_frontend_gateway_links(tmp_path: Path):
    backend = tmp_path / "users"
    frontend = tmp_path / "web" / "src" / "pages"
    gateway = tmp_path / "gateway"
    backend.mkdir()
    frontend.mkdir(parents=True)
    gateway.mkdir()

    java_file = backend / "UserController.java"
    java_file.write_text(
        """
        @RestController
        @RequestMapping("/users")
        class UserController {
            @GetMapping("/{id}")
            String getUser(@PathVariable String id) { return id; }
        }
        """
    )
    frontend_file = frontend / "users.tsx"
    frontend_file.write_text(
        """
        export async function loadUser(id: string) {
          return fetch(`/edge/users/${id}`)
        }
        """
    )
    (gateway / "application.yml").write_text(
        """
        spring:
          cloud:
            gateway:
              routes:
                - id: users
                  uri: lb://user-service
                  predicates:
                    - Path=/edge/**
                  filters:
                    - StripPrefix=1
        """
    )

    parser = ASTParser()
    java_ast = parser.parse_file(java_file, repository_id="users", repository_root=backend)
    frontend_ast = parser.parse_file(
        frontend_file, repository_id="web", repository_root=tmp_path / "web"
    )
    assert java_ast is not None
    assert frontend_ast is not None

    detected = EndpointDetector().detect([java_ast, frontend_ast])
    endpoints = [_endpoint_info(endpoint) for endpoint in detected]
    assert [(ep.method, ep.path) for ep in endpoints] == [("GET", "/users/{id}")]

    calls, routes, links = AttackSurfaceAnalyzer().analyze(
        [backend, tmp_path / "web", gateway],
        [java_ast, frontend_ast],
        endpoints,
    )
    assert [(call.method, call.path) for call in calls] == [("GET", "/edge/users/{dynamic}")]
    assert routes[0].id == "users"
    assert {link.source_kind for link in links} == {"frontend_call", "gateway_route"}
    assert any(
        link.source_kind == "frontend_call" and link.match_kind == "gateway_transform"
        for link in links
    )
    assert endpoints[0].called_by_frontend is True
    assert endpoints[0].exposed_via_gateway is True


def test_gateway_rewrite_path_correlates_public_frontend_call(tmp_path: Path):
    frontend = tmp_path / "web" / "src"
    gateway = tmp_path / "gateway"
    frontend.mkdir(parents=True)
    gateway.mkdir()
    frontend_file = frontend / "orders.ts"
    frontend_file.write_text('fetch("/public/orders/42")\n')
    (gateway / "application.yml").write_text(
        """
spring:
  cloud:
    gateway:
      routes:
        - id: orders
          uri: lb://orders
          predicates:
            - Path=/public/orders/**
          filters:
            - RewritePath=/public/(?<segment>.*), /${segment}
"""
    )
    ast = ASTParser().parse_file(
        frontend_file,
        repository_id="web",
        repository_root=tmp_path / "web",
    )
    assert ast is not None
    endpoint = EndpointInfo(
        path="/orders/{id}",
        method="GET",
        handler_function="OrderController.getOrder",
        file_path=str(tmp_path / "orders" / "OrderController.java"),
        repository_id="orders",
    )

    _, _, links = AttackSurfaceAnalyzer().analyze([tmp_path / "web", gateway], [ast], [endpoint])

    assert endpoint.called_by_frontend
    assert any(
        link.source_kind == "frontend_call" and link.match_kind == "gateway_transform"
        for link in links
    )


def test_request_mapping_named_path_and_method(tmp_path: Path):
    source = tmp_path / "AdminController.kt"
    source.write_text(
        """
        @RestController
        @RequestMapping(path = [\"/admin\"])
        class AdminController {
            @RequestMapping(path = [\"/jobs\"], method = [RequestMethod.POST])
            fun runJob() = \"ok\"
        }
        """
    )
    ast = ASTParser().parse_file(source)
    assert ast is not None
    endpoints = EndpointDetector().detect([ast])
    assert any(ep.path == "/admin/jobs" and ep.method == "POST" for ep in endpoints)
