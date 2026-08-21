"""Strict package-coordinate extraction for canonical SCIP symbol strings."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote


@dataclass(frozen=True, order=True)
class ScipPackageCoordinate:
    scheme: str
    manager: str
    name: str
    version: str

    @property
    def canonical(self) -> str:
        return " ".join(
            _escape_space(value) for value in (self.scheme, self.manager, self.name, self.version)
        )

    @property
    def family(self) -> tuple[str, str, str]:
        return (self.scheme, self.manager, self.name)

    @property
    def node_id(self) -> str:
        encoded = [
            quote(value, safe="") for value in (self.scheme, self.manager, self.name, self.version)
        ]
        return f"scip-package:{encoded[0]}:{encoded[1]}:{encoded[2]}@{encoded[3]}"


@dataclass(frozen=True)
class ScipSymbol:
    raw: str
    scheme: str
    package: ScipPackageCoordinate | None
    descriptors: str = ""
    local_id: str = ""


def parse_scip_symbol(value: str) -> ScipSymbol | None:
    """Parse the package portion defined by the official SCIP grammar.

    Package fields escape literal spaces by doubling them. Descriptor text is
    retained verbatim because display names must come from SymbolInformation,
    not by heuristically decoding descriptors.
    """

    if value.startswith("local "):
        local_id = value.removeprefix("local ")
        return (
            ScipSymbol(raw=value, scheme="local", package=None, local_id=local_id)
            if local_id
            else None
        )
    fields = _split_package_prefix(value)
    if fields is None:
        return None
    scheme, manager, name, version, descriptors = fields
    if not scheme or scheme.startswith("local") or not descriptors:
        return None
    if any(not item for item in (manager, name, version)):
        return None
    package = ScipPackageCoordinate(scheme, manager, name, version)
    return ScipSymbol(
        raw=value,
        scheme=scheme,
        package=package,
        descriptors=descriptors,
    )


def _split_package_prefix(value: str) -> tuple[str, str, str, str, str] | None:
    components: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character != " ":
            current.append(character)
            index += 1
            continue
        if index + 1 < len(value) and value[index + 1] == " ":
            current.append(" ")
            index += 2
            continue
        components.append("".join(current))
        current = []
        index += 1
        if len(components) == 4:
            descriptors = value[index:]
            return (
                components[0],
                components[1],
                components[2],
                components[3],
                descriptors,
            )
    return None


def _escape_space(value: str) -> str:
    return value.replace(" ", "  ")
