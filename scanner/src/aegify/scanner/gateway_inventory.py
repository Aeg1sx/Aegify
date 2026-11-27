"""Review static gateway declarations against explicit service ownership in a workspace."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Collection, Iterator
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml

from aegify.models import GatewayConfigReview, GatewayInventory, GatewayOwnership
from aegify.scanner.spring_properties import property_entries
from aegify.source_files import read_regular_source

MAX_FILES = 128
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_ROUTES = 4096
SPRING_SCHEMAS = (
    "spring.cloud.gateway.routes",
    "spring.cloud.gateway.mvc.routes",
    "spring.cloud.gateway.server.webflux.routes",
    "spring.cloud.gateway.server.webmvc.routes",
)
_CONFIG = re.compile(
    r"(?:(?:application|bootstrap)(?:-[\w.-]+)?\.(?:ya?ml|properties)|kong\.(?:ya?ml|json))", re.I
)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_ROUTE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", re.ASCII)


def conventional_config(path: Path) -> bool:
    return _CONFIG.fullmatch(path.name) is not None


def canonical_host(value: object) -> str | None:
    if not isinstance(value, str) or not value.isascii():
        return None
    host = value.lower().removesuffix(".")
    if 0 < len(host) <= 253 and all(_LABEL.fullmatch(label) for label in host.split(".")):
        return host
    return None


class _Loader(yaml.BaseLoader):
    """Bound parsing work before building a tree. Never construct application objects."""

    def __init__(self, stream: bytes) -> None:
        super().__init__(stream)
        self.nodes = 0
        self.depth = 0

    def compose_node(self, parent: Any, index: Any) -> yaml.Node | None:
        self.nodes += 1
        if self.check_event(yaml.AliasEvent) or self.nodes > 20_000 or self.depth >= 40:
            raise ValueError("unsupported_yaml_structure")
        self.depth += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1


class _Mapping(dict[str, Any]):
    def __init__(self, line: int) -> None:
        super().__init__()
        self.line = line


def _unpack(node: yaml.Node) -> Any:
    if not node.tag.startswith("tag:yaml.org,2002:"):
        raise ValueError("unsupported_tag")
    if isinstance(node, yaml.MappingNode):
        mapping = _Mapping(node.start_mark.line + 1)
        for key, child in node.value:
            if not isinstance(key, yaml.ScalarNode) or key.value in mapping or key.value == "<<":
                raise ValueError("invalid_mapping")
            mapping[key.value] = _unpack(child)
        return mapping
    if isinstance(node, yaml.SequenceNode):
        return [_unpack(item) for item in node.value]
    if isinstance(node, yaml.ScalarNode):
        return node.value
    raise ValueError("invalid_node")


def config_documents(raw: bytes) -> Iterator[Any]:
    for node in yaml.compose_all(raw, Loader=_Loader):
        yield _unpack(node)


def _sections(mapping: _Mapping, dotted: str) -> Iterator[Any]:
    # Spring Boot accepts nested keys, dot-separated keys and mixed forms.
    for key, value in mapping.items():
        if key == dotted:
            yield value
        elif isinstance(value, _Mapping) and dotted.startswith(key + "."):
            yield from _sections(value, dotted[len(key) + 1 :])


def _entities(mapping: _Mapping, key: str) -> list[_Mapping]:
    values = mapping.get(key, [])
    if not isinstance(values, list) or not all(isinstance(value, _Mapping) for value in values):
        raise ValueError("invalid_entity_list")
    return values


def _uri_host(value: object, schemes: set[str]) -> str | None:
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 for c in value):
        return None
    try:
        uri = urlsplit(value)
        if uri.scheme not in schemes or not uri.netloc or "\\" in uri.netloc:
            return None
        _ = uri.port  # Reject invalid port syntax before attributing the route.
        return canonical_host(uri.hostname)
    except ValueError:
        return None


class _Reviewer:
    def __init__(self, owners: dict[str, list[str]], file: GatewayConfigReview) -> None:
        self.owners = owners
        self.file = file
        self.recognized = False

    def route(
        self,
        route: _Mapping,
        schema: str,
        document: int,
        name_key: str,
        host: str | None,
        reason: str = "dynamic_or_unsupported_destination",
    ) -> None:
        owners = self.owners.get(host, []) if host else []
        name = route.get(name_key)
        status: Literal["resolved", "unresolved", "ambiguous"] = "unresolved"
        if len(owners) > 1:
            status, reason = "ambiguous", "multiple_manifest_owners"
        elif owners:
            status, reason = "resolved", "manifest_service_name"
        elif host:
            reason = "no_manifest_owner"
        elif reason in {
            "ambiguous_service_ref",
            "conflicting_service_ref",
            "conflicting_service_destination",
        }:
            status = "ambiguous"
        self.file.routes.append(
            GatewayOwnership(
                schema_path=schema,
                document=document,
                line=route.line,
                route_name=name if isinstance(name, str) and _ROUTE_NAME.fullmatch(name) else None,
                status=status,
                reason=reason,
                repository_ids=owners,
            )
        )

    def review(self, data: _Mapping, document: int) -> None:
        for schema in SPRING_SCHEMAS:
            sections = list(_sections(data, schema))
            if not sections:
                continue
            self.recognized = True
            if len(sections) != 1 or not isinstance(sections[0], list):
                raise ValueError("invalid_route_section")
            for route in sections[0]:
                if not isinstance(route, _Mapping):
                    raise ValueError("invalid_route")
                host = _uri_host(route.get("uri"), {"lb", "http", "https", "ws", "wss"})
                self.route(route, schema, document, "id", host)
        if "_format_version" in data:
            self.recognized = True
            version = data["_format_version"]
            if version not in ("1.1", "3.0"):
                self.file.diagnostics.append("unsupported_kong_format")
                return
            self.kong(data, document, "kong." + version)

    def spring_properties(self, raw: bytes) -> None:
        declarations: dict[tuple[int, str, int], _Mapping] = {}
        for document, line, key, value in property_entries(raw):
            match = re.fullmatch(r"(spring\.cloud\.gateway\.[a-z.]+)\[([0-9]{1,9})\]\.(.+)", key)
            if not match or match[1] not in SPRING_SCHEMAS:
                continue
            self.recognized = True
            identity = (document, match[1], int(match[2]))
            route = declarations.setdefault(identity, _Mapping(line))
            field = match[3]
            if field in {"id", "uri"}:
                route[field] = value
                if field == "uri":
                    route.line = line
        for (document, schema, _), route in declarations.items():
            host = _uri_host(route.get("uri"), {"lb", "http", "https", "ws", "wss"})
            self.route(route, schema, document, "id", host)

    def kong(self, data: _Mapping, document: int, schema: str) -> None:
        pools = {canonical_host(item.get("name")) for item in _entities(data, "upstreams")}
        by_ref: dict[tuple[str, str], list[_Mapping]] = defaultdict(list)
        for service in _entities(data, "services"):
            for key in ("name", "id"):
                identifier = service.get(key)
                if isinstance(identifier, str):
                    by_ref[key, identifier].append(service)
            for route in _entities(service, "routes"):
                if "service" in route:
                    self.route(route, schema, document, "name", None, "conflicting_service_ref")
                else:
                    self.kong_route(route, service, pools, document, schema)
        for route in _entities(data, "routes"):
            ref = route.get("service")
            candidates: list[_Mapping] = []
            if isinstance(ref, str):
                candidates = by_ref["name", ref] + by_ref["id", ref]
            elif isinstance(ref, _Mapping) and len(ref) == 1:
                key, value = next(iter(ref.items()))
                if isinstance(value, str):
                    candidates = by_ref[key, value]
            if len(candidates) == 1:
                self.kong_route(route, candidates[0], pools, document, schema)
            else:
                reason = "ambiguous_service_ref" if candidates else "unresolved_service_ref"
                self.route(route, schema, document, "name", None, reason)

    def kong_route(
        self,
        route: _Mapping,
        service: _Mapping,
        pools: set[str | None],
        document: int,
        schema: str,
    ) -> None:
        if "url" in service and "host" in service:
            self.route(route, schema, document, "name", None, "conflicting_service_destination")
            return
        if "url" in service:
            host = _uri_host(service["url"], {"http", "https", "ws", "wss", "grpc", "grpcs"})
        else:
            host = canonical_host(service.get("host"))
        if host and host in pools:
            self.route(route, schema, document, "name", None, "kong_upstream_pool")
        else:
            self.route(route, schema, document, "name", host)


# (workspace repository ID, canonical root, repository-relative path, explicit declaration)
type ConfigInput = tuple[str, Path, Path, bool]


def config_inputs(
    repository_id: str,
    root: Path,
    files: list[Path],
    declared: list[str] | None = None,
    excludes: Collection[str] = (),
) -> list[ConfigInput]:
    root_path = root.absolute()
    selected: set[Path] = set()
    for path in files:
        if conventional_config(path) and path.absolute().is_relative_to(root_path):
            selected.add(path.absolute().relative_to(root_path))
    explicit = {Path(path) for path in declared or []}
    canonical = root.resolve()
    return [
        (repository_id, canonical, path, path in explicit)
        for path in sorted(selected | explicit)
        if ".." not in path.parts
        and ".git" not in path.parts
        and not any(fnmatch(path.as_posix(), pattern) for pattern in excludes)
    ]


def review_gateway_configs(
    inputs: list[ConfigInput],
    service_names: dict[str, list[str]],
) -> GatewayInventory | None:
    owners: dict[str, list[str]] = defaultdict(list)
    for repository_id, aliases in sorted(service_names.items()):
        for name in aliases:
            owners[name].append(repository_id)

    inventory = GatewayInventory(omitted_files=max(0, len(inputs) - MAX_FILES))
    remaining_bytes = MAX_TOTAL_BYTES
    remaining_routes = MAX_ROUTES
    # Give manifest-nominated files priority when discovery reaches the file budget.
    prioritized = sorted(inputs, key=lambda item: (not item[3], item[0], item[2]))
    for repository_id, root, path, explicit in prioritized[:MAX_FILES]:
        if remaining_bytes <= 0:
            inventory.omitted_files += 1
            continue
        file = GatewayConfigReview(repository_id=repository_id, path=path.as_posix())
        reviewer = _Reviewer(owners, file)
        try:
            raw = read_regular_source(root, path, min(MAX_FILE_BYTES, remaining_bytes))
        except OSError, ValueError, NotImplementedError:
            file.diagnostics.append("unreadable_or_size_limit")
        else:
            remaining_bytes -= len(raw)
            file.sha256 = hashlib.sha256(raw).hexdigest()
            try:
                if path.suffix.lower() == ".properties":
                    reviewer.spring_properties(raw)
                else:
                    if path.suffix.lower() == ".json":
                        json.loads(raw)  # JSON input must also meet JSON syntax.
                    for document, data in enumerate(config_documents(raw), 1):
                        if isinstance(data, _Mapping):
                            reviewer.review(data, document)
            except ValueError, yaml.YAMLError, RecursionError:
                file.routes.clear()
                file.diagnostics.append("invalid_or_unsupported_configuration")
            if not reviewer.recognized and not file.diagnostics:
                if explicit or path.stem.lower() == "kong":
                    file.diagnostics.append("no_supported_gateway_declarations")
                else:
                    continue
        kept = min(remaining_routes, len(file.routes))
        inventory.omitted_routes += len(file.routes) - kept
        del file.routes[kept:]
        remaining_routes -= kept
        inventory.files.append(file)
    if not inventory.files and not inventory.omitted_files:
        return None
    if (
        inventory.omitted_files
        or inventory.omitted_routes
        or any(f.diagnostics for f in inventory.files)
    ):
        inventory.input_status = "partial"
    evidence = {"inventory": inventory.model_dump(exclude={"digest"}), "owners": owners}
    inventory.digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return inventory
