"""Parse Wrangler manifests as data and retain value-free security observations."""

from __future__ import annotations

import json
import re
import tomllib
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tree_sitter_javascript
import tree_sitter_toml
from tree_sitter import Language, Node, Parser

from aegify.models import (
    WRANGLER_PREVIEW_FIELDS,
    WRANGLER_STORAGE_FIELDS,
    FileAST,
    ParseDiagnostic,
    WranglerPreviewCollection,
    WranglerPreviewMatch,
    WranglerSetting,
    WranglerStorageCollection,
    WranglerStorageMatch,
)
from aegify.models import Language as ScanLanguage

MANIFEST_NAMES = frozenset({"wrangler.toml", "wrangler.json", "wrangler.jsonc"})
_CREDENTIAL = re.compile(
    r"(?:^|_)(?:PASSWORD|PASSWD|API_KEY|API_TOKEN|ACCESS_TOKEN|AUTH_TOKEN|REFRESH_TOKEN|"
    r"CLIENT_SECRET|SECRET(?:_KEY)?|PRIVATE_KEY|SIGNING_KEY)$",
    re.I,
)
_PLACEHOLDER = re.compile(
    r"(?:<[^<>]+>|\$\{[^{}]+\}|\{\{[^{}]+\}\}|[*•]+|\[redacted\]|"
    r"example|replace[-_ ]?me|change[-_ ]?me|your[-_ ](?:api[-_ ]key|token|password|secret))",
    re.I,
)
type KeyPath = tuple[str | int, ...]
type Locations = dict[KeyPath, int]
_LOCATION_DEPTH = 7  # env.<name>.previews.queues.producers[index].queue


class _ConfigError(ValueError):
    def __init__(self, line: int) -> None:
        self.line = line


def _json_value(node: Node, path: KeyPath, locations: Locations, depth: int) -> Any:
    line = node.start_point[0] + 1
    if depth > 64:
        raise _ConfigError(line)
    if node.type == "object":
        result: dict[str, Any] = {}
        for pair in node.named_children:
            if pair.type == "comment":
                continue
            key = pair.child_by_field_name("key")
            value = pair.child_by_field_name("value")
            if pair.type != "pair" or key is None or key.type != "string" or value is None:
                raise _ConfigError(pair.start_point[0] + 1)
            try:
                name = json.loads(key.text or b"")
            except ValueError:
                raise _ConfigError(key.start_point[0] + 1) from None
            if name in result:
                raise _ConfigError(key.start_point[0] + 1)
            child_path = (*path, name)
            if depth < _LOCATION_DEPTH:
                locations[child_path] = key.start_point[0] + 1
            result[name] = _json_value(value, child_path, locations, depth + 1)
        return result
    if node.type == "array":
        items: list[Any] = []
        expect_value = True
        for child in node.children[1:-1]:
            if child.type == "comment":
                continue
            if child.type == ",":
                if expect_value:
                    raise _ConfigError(child.start_point[0] + 1)
                expect_value = True
            else:
                item_path = (*path, len(items))
                if depth < _LOCATION_DEPTH:
                    locations[item_path] = child.start_point[0] + 1
                items.append(_json_value(child, item_path, locations, depth + 1))
                expect_value = False
        return items
    if node.type not in {"string", "number", "true", "false", "null", "unary_expression"}:
        raise _ConfigError(line)
    try:
        return json.loads(node.text or b"")
    except ValueError:
        raise _ConfigError(line) from None


def _json_document(source: bytes, locations: Locations) -> dict[str, Any]:
    # Object-literal syntax supplies positions, comments and trailing commas. Only
    # JSON members and JSON-decoded literals are admitted by _json_value.
    parser = Parser(Language(tree_sitter_javascript.language()))
    root = parser.parse(b"(" + source + b"\n)").root_node
    if root.has_error:
        raise _ConfigError(_error_line(root))
    node = root
    for expected in ("expression_statement", "parenthesized_expression", "object"):
        children = [child for child in node.named_children if child.type != "comment"]
        if len(children) != 1 or children[0].type != expected:
            raise _ConfigError(node.start_point[0] + 1)
        node = children[0]
    result: dict[str, Any] = _json_value(node, (), locations, 0)
    return result


def _error_line(node: Node) -> int:
    while not node.is_error and not node.is_missing:
        child = next((item for item in node.children if item.has_error), None)
        if child is None:
            break
        node = child
    return node.start_point[0] + 1


def _toml_key(node: Node) -> Iterator[str]:
    if node.type == "dotted_key":
        for child in node.named_children:
            yield from _toml_key(child)
    elif node.type == "bare_key":
        yield (node.text or b"").decode()
    elif node.type == "quoted_key":
        # TOML basic and literal keys have different escape rules.
        yield next(iter(tomllib.loads((node.text or b"").decode() + " = 0")))


def _toml_values(node: Node, path: KeyPath, locations: Locations) -> None:
    if len(path) >= _LOCATION_DEPTH:
        return
    if node.type == "array":
        items = (child for child in node.named_children if child.type != "comment")
        for i, item in enumerate(items):
            item_path = (*path, i)
            locations[item_path] = item.start_point[0] + 1
            _toml_values(item, item_path, locations)
        return
    for child in node.named_children:
        if child.type != "pair":
            continue
        key = child.named_children[0]
        child_path = path
        for part in _toml_key(key):
            child_path = (*child_path, part)
            locations.setdefault(child_path, key.start_point[0] + 1)
        locations[child_path] = key.start_point[0] + 1
        _toml_values(child.named_children[-1], child_path, locations)


def _toml_locations(root: Node, locations: Locations) -> None:
    _toml_values(root, (), locations)
    latest: dict[KeyPath, int] = {}
    for table in root.named_children:
        if table.type not in {"table", "table_array_element"}:
            continue
        key = table.named_children[0]
        path: KeyPath = ()
        parts = list(_toml_key(key))
        if not parts:
            continue
        for part in parts[:-1]:
            path = (*path, part)
            locations.setdefault(path, key.start_point[0] + 1)
            if path in latest:
                path = (*path, latest[path])
        path = (*path, parts[-1])
        locations[path] = key.start_point[0] + 1
        if table.type == "table_array_element":
            index = latest.get(path, -1) + 1
            latest[path] = index
            path = (*path, index)
            locations[path] = key.start_point[0] + 1
        _toml_values(table, path, locations)


def _implements_durable_object(section: dict[str, Any], document: dict[str, Any]) -> bool:
    exports = section.get("exports", document.get("exports"))
    if isinstance(exports, dict) and any(
        isinstance(item, dict)
        and item.get("type") == "durable-object"
        and item.get("state", "created") == "created"
        for item in exports.values()
    ):
        return True
    objects = section.get("durable_objects")
    bindings = objects.get("bindings") if isinstance(objects, dict) else None
    return isinstance(bindings, list) and any(
        isinstance(item, dict)
        and isinstance(item.get("class_name"), str)
        and "script_name" not in item
        for item in bindings
    )


@dataclass(frozen=True)
class _StorageLocation:
    environment: tuple[str, ...]
    scope: str
    collection: WranglerStorageCollection
    index: int
    line: int


_RESOURCE_ID = {
    "kv_namespaces": re.compile(r"[0-9a-fA-F]{32}"),
    "d1_databases": re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"),
    "r2_buckets": re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]"),
}


def _storage_key(
    collection: WranglerStorageCollection, account: str, jurisdiction: str, value: object
) -> tuple[str, str, str, str] | None:
    # Auto-provisioned targets and template expressions do not establish shared identity.
    if not isinstance(value, str) or not _RESOURCE_ID[collection].fullmatch(value):
        return None
    if collection != "r2_buckets" and set(value.replace("-", "")) == {"0"}:
        return None
    return collection, account, jurisdiction, value


def _binding_entries(
    section: dict[str, Any], prefix: KeyPath, collection: str, locations: Locations
) -> Iterator[tuple[int, KeyPath, dict[str, Any]]]:
    path = prefix
    entries: Any = section
    for key in collection.split("."):
        if not isinstance(entries, dict):
            raise _ConfigError(locations.get(path, 1))
        if key not in entries:
            return
        path = (*path, key)
        entries = entries[key]
    if not isinstance(entries, list):
        raise _ConfigError(locations.get(path, 1))
    for index, entry in enumerate(entries):
        item = (*path, index)
        if not isinstance(entry, dict):
            raise _ConfigError(locations.get(item, 1))
        yield index, item, entry


def shared_remote_storage(
    sections: list[tuple[tuple[str, ...], str, dict[str, Any]]],
    locations: Locations,
    default_account: object,
) -> Iterator[WranglerSetting]:
    """Match a local-development selector to an explicit deployment in another scope."""
    type Identity = tuple[str, str, str, str]
    deployments: dict[Identity, dict[tuple[str, ...], _StorageLocation]] = defaultdict(dict)
    remote: list[tuple[Identity, _StorageLocation, int, bool]] = []
    for prefix, scope, section in sections:
        account = section.get("account_id", default_account)
        if account is None:
            account = ""
        if not isinstance(account, str) or (
            account and not re.fullmatch(r"[0-9a-fA-F]{32}", account)
        ):
            continue
        for collection, (primary, preview) in WRANGLER_STORAGE_FIELDS.items():
            for index, item, entry in _binding_entries(section, prefix, collection, locations):
                if "remote" in entry and type(entry["remote"]) is not bool:
                    raise _ConfigError(locations.get((*item, "remote"), 1))
                for field in (primary, preview):
                    if field in entry and not isinstance(entry[field], str):
                        raise _ConfigError(locations.get((*item, field), 1))
                if not isinstance(entry.get("binding"), str) or not entry["binding"].strip():
                    continue
                jurisdiction = (
                    entry.get("jurisdiction", "default") if collection == "r2_buckets" else ""
                )
                if not isinstance(jurisdiction, str):
                    continue
                deployed = _storage_key(collection, account, jurisdiction, entry.get(primary))
                if deployed is not None and (line := locations.get((*item, primary))):
                    deployments[deployed].setdefault(
                        prefix, _StorageLocation(prefix, scope, collection, index, line)
                    )
                if entry.get("remote") is not True:
                    continue
                selector = preview if preview in entry else primary
                selected = _storage_key(collection, account, jurisdiction, entry.get(selector))
                flag = locations.get((*item, "remote"))
                if selected is not None and flag and (line := locations.get((*item, selector))):
                    remote.append(
                        (
                            selected,
                            _StorageLocation(prefix, scope, collection, index, line),
                            flag,
                            selector == preview,
                        )
                    )

    for identity, local, flag, uses_preview in remote:
        # One witness per other scope is enough. At most two groups are visited per binding.
        peer = next(
            (ref for key, ref in deployments[identity].items() if key != local.environment), None
        )
        if peer is not None:
            yield WranglerSetting(
                kind="shared_remote_storage",
                scope=local.scope,
                line=flag,
                storage_match=WranglerStorageMatch(
                    collection=local.collection,
                    index=local.index,
                    uses_preview=uses_preview,
                    selector_line=local.line,
                    peer_scope=peer.scope,
                    peer_index=peer.index,
                    peer_line=peer.line,
                ),
            )


type _PreviewTargets = dict[tuple[WranglerPreviewCollection, str, str], tuple[int, int]]


def _preview_targets(
    section: dict[str, Any], prefix: KeyPath, locations: Locations
) -> _PreviewTargets:
    targets: _PreviewTargets = {}
    for collection, primary in WRANGLER_PREVIEW_FIELDS.items():
        for index, item, entry in _binding_entries(section, prefix, collection, locations):
            value = entry.get(primary)
            if primary in entry and not isinstance(value, str):
                raise _ConfigError(locations.get((*item, primary), 1))
            if (
                not isinstance(value, str)
                or not isinstance(entry.get("binding"), str)
                or not entry["binding"].strip()
            ):
                continue
            jurisdiction = (
                entry.get("jurisdiction", "default") if collection == "r2_buckets" else ""
            )
            if not isinstance(jurisdiction, str):
                continue
            if collection == "queues.producers":
                if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", value):
                    continue
            elif _storage_key(collection, "", jurisdiction, value) is None:
                continue
            if line := locations.get((*item, primary)):
                targets.setdefault((collection, jurisdiction, value), (index, line))
    return targets


def _plaintext_settings(
    section: dict[str, Any], prefix: KeyPath, scope: str, locations: Locations
) -> Iterator[WranglerSetting]:
    variables = section.get("vars", {})
    if not isinstance(variables, dict):
        raise _ConfigError(locations.get((*prefix, "vars"), 1))
    for name, value in variables.items():
        path = (*prefix, "vars", name)
        if (
            path in locations
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name)
            and _CREDENTIAL.search(name)
            and not name.upper().startswith(("PUBLIC_", "NEXT_PUBLIC_", "PUBLISHABLE_"))
            and isinstance(value, str)
            and value.strip()
            and not _PLACEHOLDER.fullmatch(value.strip())
        ):
            yield WranglerSetting(
                kind="plaintext_binding", scope=scope, binding=name, line=locations[path]
            )


def _review_settings(document: dict[str, Any], locations: Locations) -> Iterator[WranglerSetting]:
    environments = document.get("env", {})
    if not isinstance(environments, dict):
        raise _ConfigError(locations.get(("env",), 1))
    sections: dict[tuple[str, ...], Any] = {(): document}
    sections.update({("env", name): section for name, section in environments.items()})
    reported_routes: set[tuple[KeyPath, KeyPath]] = set()
    storage_sections = []
    root_previews: _PreviewTargets = {}
    for prefix, section in sections.items():
        if not isinstance(section, dict):
            raise _ConfigError(locations.get(prefix, 1))
        scope = ".".join(prefix) if prefix else "default"
        # Only identifiers appear in retained evidence. Quoted or unbounded
        # environment names are represented by their declaration line.
        if prefix and not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", prefix[-1]):
            scope = f"environment at line {locations.get(prefix, 1)}"
        yield from _plaintext_settings(section, prefix, scope, locations)
        if "pages_build_output_dir" in document:
            continue
        storage_sections.append((prefix, scope, section))
        # Wrangler inherits the complete previews block, including an explicit empty override.
        # Deployment bindings always come from the selected Worker environment.
        previews, declaration = root_previews, "default"
        if "previews" in section:
            block = section["previews"]
            preview_path = (*prefix, "previews")
            if not isinstance(block, dict):
                raise _ConfigError(locations.get(preview_path, 1))
            yield from _plaintext_settings(block, preview_path, f"{scope}.previews", locations)
            previews, declaration = _preview_targets(block, preview_path, locations), scope
            if not prefix:
                root_previews = previews
        if previews:
            for identity, (index, line) in _preview_targets(section, prefix, locations).items():
                if witness := previews.get(identity):
                    preview_index, preview_line = witness
                    yield WranglerSetting(
                        kind="shared_preview_resource",
                        scope=declaration,
                        line=preview_line,
                        preview_match=WranglerPreviewMatch(
                            collection=identity[0],
                            index=preview_index,
                            peer_scope=scope,
                            peer_index=index,
                            peer_line=line,
                        ),
                    )
        for name in ("workers_dev", "preview_urls"):
            if name in section and type(section[name]) is not bool:
                raise _ConfigError(locations.get((*prefix, name), 1))
        if section.get("workers_dev", document.get("workers_dev")) is not False:
            continue
        if section.get("preview_urls", document.get("preview_urls")) is not True:
            continue
        if _implements_durable_object(section, document):
            continue
        workers_key = (*prefix, "workers_dev") if "workers_dev" in section else ("workers_dev",)
        preview_key = (*prefix, "preview_urls") if "preview_urls" in section else ("preview_urls",)
        sources = (workers_key, preview_key)
        if sources in reported_routes:
            continue
        reported_routes.add(sources)
        workers_line, preview_line = locations[workers_key], locations[preview_key]
        yield WranglerSetting(
            kind="version_urls",
            scope=scope,
            workers_dev_line=workers_line,
            preview_urls_line=preview_line,
            line=preview_line if "preview_urls" in section else workers_line,
        )
    yield from shared_remote_storage(storage_sections, locations, document.get("account_id"))


def parse_manifest(path: Path, source: bytes) -> FileAST:
    ast = FileAST(file_path=str(path), language=ScanLanguage.WRANGLER)
    locations: Locations = {}
    try:
        text = source.decode("utf-8-sig")
        if path.suffix == ".toml":
            document = tomllib.loads(text)
            parser = Parser(Language(tree_sitter_toml.language()))
            tree = parser.parse(text.encode()).root_node
            if tree.has_error:
                raise _ConfigError(_error_line(tree))
            _toml_locations(tree, locations)
        else:
            document = _json_document(text.encode(), locations)
        ast.wrangler_settings = list(_review_settings(document, locations))
    except (ValueError, RecursionError) as error:
        line = max(
            1,
            min(source.count(b"\n") + 1, getattr(error, "line", 0) or getattr(error, "lineno", 1)),
        )
        ast.parse_error_count = 1
        ast.parse_diagnostics = [
            ParseDiagnostic(
                file_path=str(path),
                kind="invalid_encoding" if isinstance(error, UnicodeError) else "error",
                line_start=line,
                line_end=line,
            )
        ]
    return ast
