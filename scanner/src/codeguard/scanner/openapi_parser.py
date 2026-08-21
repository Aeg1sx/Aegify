"""OpenAPI/Swagger specification parser for endpoint extraction."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

import yaml

from codeguard.scanner.endpoint_detector import Endpoint, EndpointParam

logger = logging.getLogger(__name__)

# Patterns to identify OpenAPI/Swagger files
_OPENAPI_FILENAMES = {
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "swagger.json",
    "swagger.yaml",
    "swagger.yml",
    "api-spec.json",
    "api-spec.yaml",
    "api-spec.yml",
    "api.json",
    "api.yaml",
    "api.yml",
}

_OPENAPI_DIR_NAMES = {"swagger", "openapi", "api-docs", "specs"}

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}


def find_openapi_files(target: Path) -> list[Path]:
    """Find OpenAPI/Swagger spec files in a project directory."""
    results: list[Path] = []

    if target.is_file():
        if _is_openapi_file(target):
            results.append(target)
        return results

    for path in target.rglob("*"):
        if path.is_file() and _is_openapi_file(path):
            results.append(path)

    return results


def _is_openapi_file(path: Path) -> bool:
    """Check if a file is likely an OpenAPI/Swagger spec."""
    name = path.name.lower()

    # Check filename match
    if name in _OPENAPI_FILENAMES:
        return True

    # Check if in a swagger/openapi directory
    if any(part.lower() in _OPENAPI_DIR_NAMES for part in path.parts):
        if name.endswith((".json", ".yaml", ".yml")):
            return _has_openapi_marker(path)

    return False


def _has_openapi_marker(path: Path) -> bool:
    """Quick check if file content looks like OpenAPI."""
    try:
        content = path.read_text(errors="ignore")[:2000]
        return bool(
            re.search(r'"openapi"\s*:', content)
            or re.search(r'"swagger"\s*:', content)
            or re.search(r"openapi\s*:", content)
            or re.search(r"swagger\s*:", content)
        )
    except OSError:
        return False


def parse_openapi_file(path: Path) -> list[Endpoint]:
    """Parse an OpenAPI/Swagger spec file and extract endpoints."""
    try:
        content = path.read_text()
        if path.suffix == ".json":
            spec = json.loads(content)
        else:
            spec = yaml.safe_load(content)
    except Exception as e:
        logger.warning("Failed to parse OpenAPI file %s: %s", path, e)
        return []

    if not isinstance(spec, dict):
        return []

    return parse_openapi_spec(spec, str(path))


def parse_openapi_spec(spec: dict[str, Any], source_path: str = "") -> list[Endpoint]:
    """Parse an OpenAPI/Swagger spec dict and extract endpoints."""
    endpoints: list[Endpoint] = []

    # Determine spec version
    version = spec.get("openapi", spec.get("swagger", ""))
    is_swagger2 = str(version).startswith("2")

    # Get base path
    base_path = ""
    if is_swagger2:
        base_path = spec.get("basePath", "").rstrip("/")
    else:
        # OpenAPI 3.x servers
        servers = spec.get("servers", [])
        if servers and isinstance(servers[0], dict):
            url = servers[0].get("url", "")
            # Extract path portion only
            if url.startswith("http"):
                from urllib.parse import urlparse

                base_path = urlparse(url).path.rstrip("/")
            else:
                base_path = url.rstrip("/")

    # Parse paths
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return endpoints

    # Get global security for auth detection
    global_security = spec.get("security", [])

    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        full_path = base_path + path_str if base_path else path_str

        for method_str in HTTP_METHODS:
            operation = path_item.get(method_str)
            if not isinstance(operation, dict):
                continue

            # Extract parameters
            params = _extract_params(
                path_item.get("parameters", []),
                operation.get("parameters", []),
            )

            # Determine auth requirement
            op_security = operation.get("security", global_security)
            auth_required = bool(op_security and any(s for s in op_security if s))

            # Handler function from operationId
            operation_id = operation.get("operationId", "")
            summary = operation.get("summary", "")
            handler = operation_id or summary or f"{method_str.upper()} {full_path}"

            # Tags as middleware
            tags = operation.get("tags", [])

            endpoints.append(
                Endpoint(
                    path=full_path,
                    method=method_str.upper(),
                    handler_function=handler,
                    file_path=source_path,
                    line_start=0,
                    line_end=0,
                    framework="OpenAPI",
                    auth_required=auth_required,
                    parameters=params,
                    middleware=tags if isinstance(tags, list) else [],
                )
            )

    logger.info(
        "Parsed %d endpoints from OpenAPI spec %s (version %s)",
        len(endpoints),
        source_path,
        version,
    )
    return endpoints


def _extract_params(
    path_params: list[Any],
    op_params: list[Any],
) -> list[EndpointParam]:
    """Extract parameters from OpenAPI parameter definitions."""
    params: list[EndpointParam] = []
    seen: set[str] = set()

    for param_list in [op_params, path_params]:  # op_params override path_params
        if not isinstance(param_list, list):
            continue
        for param in param_list:
            if not isinstance(param, dict):
                continue
            name = param.get("name", "")
            if not name or name in seen:
                continue
            seen.add(name)

            raw_location = param.get("in", "unknown")
            location = raw_location if isinstance(raw_location, str) else "unknown"
            # Map OpenAPI locations to our format
            loc_map = {
                "path": "path",
                "query": "query",
                "header": "header",
                "body": "body",
                "cookie": "cookie",
            }
            location = loc_map.get(location, location)

            # Determine type
            schema = param.get("schema", param)
            param_type = schema.get("type", "")

            params.append(EndpointParam(name=name, location=location, param_type=param_type))

    return params
