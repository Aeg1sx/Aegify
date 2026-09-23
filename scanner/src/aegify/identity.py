"""Versioned, repository-qualified finding identities shared with the importer."""

from __future__ import annotations

import hashlib
import json
import re

_WHITESPACE = " \t\r\n\f\v"


def normalize_identity_path(value: str) -> str:
    value = value.replace("\\", "/")
    scheme = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*://)(.*)$", value)
    prefix = (
        scheme[1] + ("/" if scheme[2].startswith("/") else "")
        if scheme
        else "//"
        if value.startswith("//")
        else "/"
        if value.startswith("/")
        else ""
    )
    body = scheme[2] if scheme else value
    return prefix + "/".join(part for part in body.split("/") if part not in {"", "."})


def relative_identity_path(value: str) -> str:
    path = normalize_identity_path(value)
    if (
        not path
        or path.startswith("/")
        or ":" in path.split("/", 1)[0]
        or ".." in path.split("/")
        or any(ord(character) < 32 for character in path)
    ):
        return ""
    return path


def finding_fingerprint_v2(
    rule_id: str, repository_id: str, module_path: str, file_path: str, evidence: str
) -> str:
    path = relative_identity_path(module_path) or normalize_identity_path(file_path)
    # Collapsing whitespace inside source can merge different string literals.
    # Keep retained evidence intact; only normalize line endings and outer space.
    normalized_evidence = evidence.replace("\r\n", "\n").replace("\r", "\n").strip(_WHITESPACE)
    material = [
        "aegify-finding/v2",
        rule_id.strip(_WHITESPACE),
        repository_id.strip(_WHITESPACE),
        path,
        normalized_evidence,
    ]
    encoded = json.dumps(material, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()
