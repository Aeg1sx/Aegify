"""Strict compiler-classpath import and bounded JVM classfile analysis."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, field_validator

from codeguard.models import FileAST, SemanticRelationship
from codeguard.scanner.workspace import JvmClasspathArtifact, WorkspaceRepository
from codeguard.semantic.jvm_dependencies import JvmArtifactCoordinate
from codeguard.semantic.signatures import type_compatibility


class JvmClasspathCoordinate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manager: Literal["maven"] = "maven"
    group: str = Field(min_length=1, max_length=500)
    artifact: str = Field(min_length=1, max_length=500)
    version: str = Field(min_length=1, max_length=500)

    @property
    def normalized(self) -> JvmArtifactCoordinate:
        return JvmArtifactCoordinate(
            self.manager,
            self.group,
            self.artifact,
            self.version,
        )


class JvmClasspathProducer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    version: str = Field(default="", max_length=200)


class JvmClasspathSnapshotEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str
    scope: Literal["compile", "provided", "runtime", "test"] = "compile"
    build_root: str = "root"
    module: str = "root"
    coordinate: JvmClasspathCoordinate | None = None

    @field_validator("path", "build_root", "module")
    @classmethod
    def require_beneath_snapshot(cls, value: str) -> str:
        path = PurePosixPath(value.replace("\\", "/"))
        if not value or path.is_absolute() or ".." in path.parts:
            raise ValueError("classpath paths must stay beneath the snapshot directory")
        return path.as_posix()

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("sha256 must contain 64 lowercase hexadecimal characters")
        return value


class JvmClasspathSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal[1] = 1
    repository_id: str
    producer: JvmClasspathProducer
    target_java: int = Field(default=17, ge=8, le=99)
    entries: list[JvmClasspathSnapshotEntry]


@dataclass
class JvmBytecodeSummary:
    snapshots: int = 0
    classpath_entries: int = 0
    entries_verified: int = 0
    entries_rejected: int = 0
    bytecode_classes: int = 0
    bytecode_methods: int = 0
    bytecode_invokes: int = 0
    declared_exceptions: int = 0
    unresolved_invokes: int = 0
    ambiguous_invokes: int = 0
    virtual_invokes: int = 0
    virtual_single_target: int = 0
    virtual_ambiguous: int = 0
    allocation_sites: int = 0
    rta_invokes: int = 0
    rta_targets: int = 0
    invokedynamic_sites: int = 0
    lambda_targets: int = 0
    unresolved_bootstraps: int = 0
    source_calls_resolved: int = 0
    source_calls_ambiguous: int = 0
    warnings: list[str] = field(default_factory=list)


@dataclass
class JvmBytecodeBundle:
    nodes: dict[str, dict[str, str | int | bool]] = field(default_factory=dict)
    relationships: list[SemanticRelationship] = field(default_factory=list)
    summary: JvmBytecodeSummary = field(default_factory=JvmBytecodeSummary)


@dataclass(frozen=True)
class _Invocation:
    owner: str
    name: str
    descriptor: str
    kind: str
    offset: int
    constant_index: int = 0
    fidelity: str = "sha256-verified-bytecode"
    bootstrap_method: str = ""


@dataclass(frozen=True)
class _Allocation:
    type_name: str
    offset: int


@dataclass(frozen=True)
class _BootstrapMethod:
    method_handle_index: int
    argument_indices: tuple[int, ...]


@dataclass
class _MethodFact:
    name: str
    descriptor: str
    access_flags: int
    exceptions: list[str] = field(default_factory=list)
    invocations: list[_Invocation] = field(default_factory=list)
    allocations: list[_Allocation] = field(default_factory=list)


@dataclass
class _ClassFact:
    internal_name: str
    super_name: str
    interfaces: list[str]
    access_flags: int
    major_version: int
    methods: list[_MethodFact]


@dataclass
class _LoadedClass:
    artifact_node: str
    jar_path: str
    fact: _ClassFact
    class_node: str


class _ClassFormatError(ValueError):
    pass


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.position + size > len(self.data):
            raise _ClassFormatError("truncated classfile")
        value = self.data[self.position : self.position + size]
        self.position += size
        return value

    def u1(self) -> int:
        return self.take(1)[0]

    def u2(self) -> int:
        return int.from_bytes(self.take(2), byteorder="big")

    def u4(self) -> int:
        return int.from_bytes(self.take(4), byteorder="big")


class _ClassFileParser:
    _TWO_BYTE_OPERANDS = (
        set(range(0x99, 0xA9))
        | {0x11, 0x13, 0x14}
        | set(range(0xB2, 0xB9))
        | {0xBB, 0xBD, 0xC0, 0xC1, 0xC6, 0xC7}
    )
    _ONE_BYTE_OPERANDS = {0x10, 0x12, 0xA9, 0xBC} | set(range(0x15, 0x1A)) | set(range(0x36, 0x3B))

    def __init__(self, max_code_bytes: int) -> None:
        self.max_code_bytes = max_code_bytes
        self.constants: list[tuple[object, ...] | None] = []

    def parse(self, data: bytes) -> _ClassFact:
        reader = _Reader(data)
        if reader.u4() != 0xCAFEBABE:
            raise _ClassFormatError("invalid classfile magic")
        reader.u2()
        major = reader.u2()
        count = reader.u2()
        if count <= 1 or count > 65_535:
            raise _ClassFormatError("invalid constant-pool size")
        self.constants = [None] * count
        index = 1
        while index < count:
            tag = reader.u1()
            if tag == 1:
                length = reader.u2()
                self.constants[index] = (
                    tag,
                    reader.take(length).decode("utf-8", errors="replace"),
                )
            elif tag in {3, 4}:
                self.constants[index] = (tag, reader.take(4))
            elif tag in {5, 6}:
                self.constants[index] = (tag, reader.take(8))
                index += 1
            elif tag in {7, 8, 16, 19, 20}:
                self.constants[index] = (tag, reader.u2())
            elif tag in {9, 10, 11, 12, 17, 18}:
                self.constants[index] = (tag, reader.u2(), reader.u2())
            elif tag == 15:
                self.constants[index] = (tag, reader.u1(), reader.u2())
            else:
                raise _ClassFormatError(f"unsupported constant-pool tag: {tag}")
            index += 1

        access = reader.u2()
        this_class = self._class_name(reader.u2())
        super_index = reader.u2()
        super_name = self._class_name(super_index) if super_index else ""
        interfaces = [self._class_name(reader.u2()) for _ in range(reader.u2())]
        for _ in range(reader.u2()):
            self._skip_member(reader)
        methods = [self._parse_method(reader) for _ in range(reader.u2())]
        bootstrap_methods = self._parse_class_attributes(reader)
        for method in methods:
            method.invocations = [
                self._resolve_invokedynamic(invocation, bootstrap_methods)
                if invocation.kind == "dynamic"
                else invocation
                for invocation in method.invocations
            ]
        return _ClassFact(
            internal_name=this_class,
            super_name=super_name,
            interfaces=interfaces,
            access_flags=access,
            major_version=major,
            methods=methods,
        )

    def _parse_method(self, reader: _Reader) -> _MethodFact:
        access = reader.u2()
        name = self._utf8(reader.u2())
        descriptor = self._utf8(reader.u2())
        exceptions: list[str] = []
        invocations: list[_Invocation] = []
        allocations: list[_Allocation] = []
        for _ in range(reader.u2()):
            attribute_name = self._utf8(reader.u2())
            payload = reader.take(reader.u4())
            if attribute_name == "Exceptions":
                attribute = _Reader(payload)
                exceptions = [self._class_name(attribute.u2()) for _ in range(attribute.u2())]
            elif attribute_name == "Code":
                attribute = _Reader(payload)
                attribute.u2()
                attribute.u2()
                code_size = attribute.u4()
                if code_size > self.max_code_bytes:
                    raise _ClassFormatError(f"method code exceeds {self.max_code_bytes} bytes")
                invocations, allocations = self._parse_code(attribute.take(code_size))
        return _MethodFact(name, descriptor, access, exceptions, invocations, allocations)

    def _skip_member(self, reader: _Reader) -> None:
        reader.u2()
        reader.u2()
        reader.u2()
        self._skip_attributes(reader)

    def _skip_attributes(self, reader: _Reader) -> None:
        for _ in range(reader.u2()):
            reader.u2()
            reader.take(reader.u4())

    def _parse_class_attributes(self, reader: _Reader) -> list[_BootstrapMethod]:
        bootstrap_methods: list[_BootstrapMethod] = []
        seen = False
        for _ in range(reader.u2()):
            attribute_name = self._utf8(reader.u2())
            payload = reader.take(reader.u4())
            if attribute_name != "BootstrapMethods":
                continue
            if seen:
                raise _ClassFormatError("duplicate BootstrapMethods attribute")
            seen = True
            attribute = _Reader(payload)
            for _ in range(attribute.u2()):
                method_handle_index = attribute.u2()
                argument_indices = tuple(attribute.u2() for _ in range(attribute.u2()))
                bootstrap_methods.append(_BootstrapMethod(method_handle_index, argument_indices))
            if attribute.position != len(payload):
                raise _ClassFormatError("trailing BootstrapMethods payload")
        return bootstrap_methods

    def _parse_code(self, code: bytes) -> tuple[list[_Invocation], list[_Allocation]]:
        result: list[_Invocation] = []
        allocations: list[_Allocation] = []
        position = 0
        while position < len(code):
            offset = position
            opcode = code[position]
            position += 1
            if opcode in {0xB6, 0xB7, 0xB8, 0xB9, 0xBA}:
                if position + 2 > len(code):
                    break
                constant_index = struct.unpack(">H", code[position : position + 2])[0]
                reference = self._method_reference(constant_index)
                if reference is not None:
                    owner, name, descriptor = reference
                    kind = {
                        0xB6: "virtual",
                        0xB7: "special",
                        0xB8: "static",
                        0xB9: "interface",
                        0xBA: "dynamic",
                    }[opcode]
                    result.append(
                        _Invocation(
                            owner,
                            name,
                            descriptor,
                            kind,
                            offset,
                            constant_index,
                        )
                    )
                position += 4 if opcode in {0xB9, 0xBA} else 2
                continue
            if opcode == 0xBB:
                if position + 2 > len(code):
                    break
                constant_index = struct.unpack(">H", code[position : position + 2])[0]
                allocations.append(_Allocation(self._class_name(constant_index), offset))
                position += 2
                continue
            if opcode == 0xAA:
                padding = (4 - (position % 4)) % 4
                position += padding
                if position + 12 > len(code):
                    break
                low = struct.unpack(">i", code[position + 4 : position + 8])[0]
                high = struct.unpack(">i", code[position + 8 : position + 12])[0]
                count = high - low + 1
                if count < 0 or count > 1_000_000:
                    break
                position += 12 + count * 4
                continue
            if opcode == 0xAB:
                padding = (4 - (position % 4)) % 4
                position += padding
                if position + 8 > len(code):
                    break
                pairs = struct.unpack(">i", code[position + 4 : position + 8])[0]
                if pairs < 0 or pairs > 1_000_000:
                    break
                position += 8 + pairs * 8
                continue
            if opcode == 0xC4:
                if position >= len(code):
                    break
                subopcode = code[position]
                position += 5 if subopcode == 0x84 else 3
                continue
            if opcode in self._ONE_BYTE_OPERANDS:
                position += 1
            elif opcode in self._TWO_BYTE_OPERANDS or opcode == 0x84:
                position += 2
            elif opcode in {0xB9, 0xBA, 0xC8, 0xC9}:
                position += 4
            elif opcode == 0xC5:
                position += 3
            if position > len(code):
                break
        return result, allocations

    def _utf8(self, index: int) -> str:
        value = self._constant(index)
        if value[0] != 1:
            raise _ClassFormatError(f"constant #{index} is not UTF-8")
        return str(value[1])

    def _class_name(self, index: int) -> str:
        value = self._constant(index)
        if value[0] != 7:
            raise _ClassFormatError(f"constant #{index} is not a class")
        return self._utf8(self._constant_index(value[1]))

    def _method_reference(self, index: int) -> tuple[str, str, str] | None:
        value = self._constant(index)
        if value[0] in {10, 11}:
            owner = self._class_name(self._constant_index(value[1]))
            name, descriptor = self._name_and_type(self._constant_index(value[2]))
            return owner, name, descriptor
        if value[0] == 18:
            name, descriptor = self._name_and_type(self._constant_index(value[2]))
            return "<dynamic>", name, descriptor
        return None

    def _resolve_invokedynamic(
        self,
        invocation: _Invocation,
        bootstrap_methods: list[_BootstrapMethod],
    ) -> _Invocation:
        value = self._constant(invocation.constant_index)
        if value[0] != 18:
            raise _ClassFormatError("invokedynamic does not reference CONSTANT_InvokeDynamic")
        bootstrap_index = self._constant_index(value[1])
        if bootstrap_index < 0 or bootstrap_index >= len(bootstrap_methods):
            raise _ClassFormatError(
                f"invokedynamic bootstrap index out of range: {bootstrap_index}"
            )
        bootstrap = bootstrap_methods[bootstrap_index]
        _, owner, name, descriptor = self._method_handle(bootstrap.method_handle_index)
        bootstrap_method = f"{owner}#{name}{descriptor}"
        if owner != "java/lang/invoke/LambdaMetafactory" or name not in {
            "metafactory",
            "altMetafactory",
        }:
            return _Invocation(
                invocation.owner,
                invocation.name,
                invocation.descriptor,
                invocation.kind,
                invocation.offset,
                invocation.constant_index,
                "bytecode-invokedynamic-bootstrap-unresolved",
                bootstrap_method,
            )
        if len(bootstrap.argument_indices) < 2:
            return _Invocation(
                invocation.owner,
                invocation.name,
                invocation.descriptor,
                invocation.kind,
                invocation.offset,
                invocation.constant_index,
                "bytecode-invokedynamic-bootstrap-unresolved",
                bootstrap_method,
            )
        try:
            _, target_owner, target_name, target_descriptor = self._method_handle(
                bootstrap.argument_indices[1]
            )
        except _ClassFormatError:
            return _Invocation(
                invocation.owner,
                invocation.name,
                invocation.descriptor,
                invocation.kind,
                invocation.offset,
                invocation.constant_index,
                "bytecode-invokedynamic-bootstrap-unresolved",
                bootstrap_method,
            )
        return _Invocation(
            target_owner,
            target_name,
            target_descriptor,
            invocation.kind,
            invocation.offset,
            invocation.constant_index,
            "bytecode-lambda-metafactory",
            bootstrap_method,
        )

    def _method_handle(self, index: int) -> tuple[int, str, str, str]:
        value = self._constant(index)
        if value[0] != 15:
            raise _ClassFormatError(f"constant #{index} is not a method handle")
        reference_kind = self._constant_index(value[1])
        if reference_kind < 1 or reference_kind > 9:
            raise _ClassFormatError(f"invalid method-handle kind: {reference_kind}")
        reference = self._method_reference(self._constant_index(value[2]))
        if reference is None or reference[0] == "<dynamic>":
            raise _ClassFormatError("method handle does not reference a method")
        return reference_kind, *reference

    def _name_and_type(self, index: int) -> tuple[str, str]:
        value = self._constant(index)
        if value[0] != 12:
            raise _ClassFormatError(f"constant #{index} is not name-and-type")
        return self._utf8(self._constant_index(value[1])), self._utf8(
            self._constant_index(value[2])
        )

    @staticmethod
    def _constant_index(value: object) -> int:
        if not isinstance(value, int):
            raise _ClassFormatError("constant-pool reference is not an integer")
        return value

    def _constant(self, index: int) -> tuple[object, ...]:
        if index <= 0 or index >= len(self.constants):
            raise _ClassFormatError(f"constant-pool index out of range: {index}")
        value = self.constants[index]
        if value is None:
            raise _ClassFormatError(f"constant-pool index is unusable: {index}")
        return value


class JvmBytecodeImporter:
    """Import one retained classpath snapshot without executing its JARs."""

    _SNAPSHOT_LIMIT = 10_000_000

    def load(
        self,
        artifact: JvmClasspathArtifact,
        repository: WorkspaceRepository,
    ) -> JvmBytecodeBundle:
        result = JvmBytecodeBundle()
        result.summary.snapshots = 1
        raw = artifact.path.read_bytes()
        if len(raw) > self._SNAPSHOT_LIMIT:
            raise ValueError(f"classpath snapshot exceeds {self._SNAPSHOT_LIMIT} bytes")
        snapshot = JvmClasspathSnapshot.model_validate(json.loads(raw))
        if snapshot.repository_id != repository.id:
            raise ValueError(
                f"snapshot repository {snapshot.repository_id!r} does not match {repository.id!r}"
            )
        if len(snapshot.entries) > artifact.max_entries:
            raise ValueError(
                f"classpath snapshot has {len(snapshot.entries)} entries; "
                f"limit is {artifact.max_entries}"
            )
        result.summary.classpath_entries = len(snapshot.entries)
        root = artifact.path.parent.resolve()
        total_bytes = 0
        loaded: list[_LoadedClass] = []
        class_providers: dict[str, list[_LoadedClass]] = {}
        parsed_jars: set[tuple[str, str]] = set()
        counted_jars: set[str] = set()

        for entry in snapshot.entries:
            if entry.scope == "test":
                continue
            jar = (root / entry.path).resolve()
            error = self._validate_jar(jar, root, entry, artifact)
            if error:
                result.summary.entries_rejected += 1
                result.summary.warnings.append(f"{entry.path}: {error}")
                continue
            if entry.sha256 not in counted_jars:
                total_bytes += jar.stat().st_size
                if total_bytes > artifact.max_total_bytes:
                    result.summary.entries_rejected += 1
                    result.summary.warnings.append(
                        f"{entry.path}: classpath exceeds {artifact.max_total_bytes} bytes"
                    )
                    continue
                counted_jars.add(entry.sha256)
            result.summary.entries_verified += 1
            coordinate = entry.coordinate.normalized if entry.coordinate else None
            if coordinate is None:
                coordinate = self._infer_coordinate(jar)
            artifact_node = (
                coordinate.node_id
                if coordinate is not None
                else f"jvm-classpath-entry:sha256:{entry.sha256}"
            )
            entry_node = f"jvm-jar:sha256:{entry.sha256}"
            module_node = self._module_id(repository.id, entry.build_root, entry.module)
            result.nodes[module_node] = {
                "kind": "jvm-module",
                "repository_id": repository.id,
            }
            result.nodes[artifact_node] = {
                "kind": "jvm-artifact" if coordinate else "jvm-classpath-entry",
                "sha256": entry.sha256,
                "classpath_verified": True,
            }
            if coordinate is not None:
                result.nodes[artifact_node].update(
                    {
                        "manager": coordinate.manager,
                        "group": coordinate.group,
                        "artifact": coordinate.artifact,
                        "version": coordinate.version,
                    }
                )
            result.nodes[entry_node] = {
                "kind": "jvm-jar",
                "sha256": entry.sha256,
                "size_bytes": jar.stat().st_size,
                "file_path": entry.path,
                "producer": snapshot.producer.name,
                "producer_version": snapshot.producer.version,
            }
            self._relationship(
                result,
                module_node,
                artifact_node,
                "loads-jvm-artifact",
                repository.id,
                entry.path,
                "compiler-classpath-snapshot",
                1.0,
            )
            self._relationship(
                result,
                artifact_node,
                entry_node,
                "classpath-materialized-as",
                repository.id,
                entry.path,
                "sha256-verified-artifact",
                1.0,
            )
            parse_identity = (entry.sha256, artifact_node)
            if parse_identity in parsed_jars:
                continue
            parsed_jars.add(parse_identity)
            jar_classes = self._parse_jar(
                jar,
                entry.path,
                artifact_node,
                snapshot.target_java,
                artifact,
                result,
            )
            for item in jar_classes:
                loaded.append(item)
                class_providers.setdefault(item.fact.internal_name, []).append(item)

        self._emit_class_graph(result, loaded, class_providers, repository.id)
        return result

    @staticmethod
    def _validate_jar(
        jar: Path,
        root: Path,
        entry: JvmClasspathSnapshotEntry,
        artifact: JvmClasspathArtifact,
    ) -> str:
        if not jar.is_relative_to(root):
            return "path escaped snapshot directory"
        if jar.is_symlink():
            return "symbolic links are not accepted"
        if not jar.is_file():
            return "JAR does not exist or is not a regular file"
        size = jar.stat().st_size
        if size > artifact.max_jar_bytes:
            return f"JAR exceeds {artifact.max_jar_bytes} bytes"
        digest = hashlib.sha256()
        with jar.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1_048_576), b""):
                digest.update(chunk)
        if digest.hexdigest() != entry.sha256:
            return "SHA-256 mismatch"
        return ""

    def _parse_jar(
        self,
        jar: Path,
        display_path: str,
        artifact_node: str,
        target_java: int,
        policy: JvmClasspathArtifact,
        result: JvmBytecodeBundle,
    ) -> list[_LoadedClass]:
        loaded: list[_LoadedClass] = []
        try:
            with zipfile.ZipFile(jar) as archive:
                selected = self._selected_classes(archive, target_java, result)
                for info in selected:
                    if result.summary.bytecode_classes >= policy.max_classes:
                        result.summary.warnings.append(
                            f"{display_path}: class count capped at {policy.max_classes}"
                        )
                        break
                    if info.file_size > policy.max_class_bytes:
                        result.summary.warnings.append(
                            f"{display_path}!{info.filename}: class exceeds "
                            f"{policy.max_class_bytes} bytes"
                        )
                        continue
                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > policy.max_compression_ratio:
                        result.summary.warnings.append(
                            f"{display_path}!{info.filename}: compression ratio "
                            f"{ratio:.1f} exceeds {policy.max_compression_ratio:.1f}"
                        )
                        continue
                    try:
                        data = archive.read(info)
                        fact = _ClassFileParser(policy.max_class_bytes).parse(data)
                    except (OSError, RuntimeError, _ClassFormatError) as error:
                        result.summary.warnings.append(f"{display_path}!{info.filename}: {error}")
                        continue
                    class_node = self._class_node(artifact_node, fact.internal_name)
                    result.nodes[class_node] = {
                        "kind": "jvm-bytecode-class",
                        "internal_name": fact.internal_name,
                        "major_version": fact.major_version,
                        "access_flags": fact.access_flags,
                        "file_path": display_path,
                    }
                    self._relationship(
                        result,
                        artifact_node,
                        class_node,
                        "contains-bytecode-class",
                        "",
                        display_path,
                        "sha256-verified-bytecode",
                        1.0,
                    )
                    item = _LoadedClass(artifact_node, display_path, fact, class_node)
                    loaded.append(item)
                    result.summary.bytecode_classes += 1
        except (OSError, zipfile.BadZipFile) as error:
            result.summary.warnings.append(f"{display_path}: {error}")
        return loaded

    def _emit_class_graph(
        self,
        result: JvmBytecodeBundle,
        loaded: list[_LoadedClass],
        providers: dict[str, list[_LoadedClass]],
        repository_id: str,
    ) -> None:
        defined_methods: dict[tuple[str, str, str, str], str] = {}
        instantiated_types = {
            allocation.type_name
            for item in loaded
            for method in item.fact.methods
            for allocation in method.allocations
        }
        for item in loaded:
            for method in item.fact.methods:
                method_node = self._method_node(
                    item.artifact_node,
                    item.fact.internal_name,
                    method.name,
                    method.descriptor,
                )
                defined_methods[
                    (
                        item.artifact_node,
                        item.fact.internal_name,
                        method.name,
                        method.descriptor,
                    )
                ] = method_node
                result.nodes[method_node] = {
                    "kind": "jvm-bytecode-method",
                    "artifact_node": item.artifact_node,
                    "owner": item.fact.internal_name,
                    "method_name": method.name,
                    "descriptor": method.descriptor,
                    "access_flags": method.access_flags,
                    "file_path": item.jar_path,
                }
                self._relationship(
                    result,
                    item.class_node,
                    method_node,
                    "declares-bytecode-method",
                    repository_id,
                    item.jar_path,
                    "sha256-verified-bytecode",
                    1.0,
                )
                result.summary.bytecode_methods += 1

        for item in loaded:
            self._emit_hierarchy(result, item, providers, repository_id)
            for method in item.fact.methods:
                source = defined_methods[
                    (
                        item.artifact_node,
                        item.fact.internal_name,
                        method.name,
                        method.descriptor,
                    )
                ]
                for exception in method.exceptions:
                    target = self._type_target(exception, providers, result)
                    self._relationship(
                        result,
                        source,
                        target,
                        "bytecode-declares-throws",
                        repository_id,
                        item.jar_path,
                        "classfile-exceptions-attribute",
                        1.0,
                    )
                    result.summary.declared_exceptions += 1
                for allocation in method.allocations:
                    target = self._type_target(allocation.type_name, providers, result)
                    self._relationship(
                        result,
                        source,
                        target,
                        "bytecode-allocates",
                        repository_id,
                        item.jar_path,
                        "sha256-verified-bytecode",
                        1.0,
                        allocation.offset,
                        "new",
                    )
                    result.summary.allocation_sites += 1
                for invocation in method.invocations:
                    if invocation.kind == "dynamic":
                        result.summary.invokedynamic_sites += 1
                        if invocation.fidelity == "bytecode-lambda-metafactory":
                            result.summary.lambda_targets += 1
                        else:
                            result.summary.unresolved_bootstraps += 1
                    if invocation.kind in {"virtual", "interface"}:
                        self._emit_virtual_invocation(
                            result,
                            source,
                            invocation,
                            loaded,
                            providers,
                            defined_methods,
                            instantiated_types,
                            repository_id,
                            item.jar_path,
                        )
                    else:
                        self._emit_direct_invocation(
                            result,
                            source,
                            invocation,
                            providers,
                            repository_id,
                            item.jar_path,
                        )
                    result.summary.bytecode_invokes += 1

    def _emit_direct_invocation(
        self,
        result: JvmBytecodeBundle,
        source: str,
        invocation: _Invocation,
        providers: dict[str, list[_LoadedClass]],
        repository_id: str,
        file_path: str,
    ) -> None:
        targets = providers.get(invocation.owner, [])
        resolved_fidelity = (
            invocation.fidelity if invocation.kind == "dynamic" else "sha256-verified-bytecode"
        )
        if len(targets) == 1:
            provider = targets[0]
            target = self._method_node(
                provider.artifact_node,
                invocation.owner,
                invocation.name,
                invocation.descriptor,
            )
            result.nodes.setdefault(
                target,
                self._method_reference_attributes(invocation, "jvm-bytecode-method-reference"),
            )
            self._relationship(
                result,
                source,
                target,
                "bytecode-invoke",
                repository_id,
                file_path,
                resolved_fidelity,
                0.98 if invocation.kind == "dynamic" else 1.0,
                invocation.offset,
                invocation.kind,
                invocation.bootstrap_method,
            )
            return
        if not targets:
            unresolved_fidelity = "classpath-target-unresolved"
            if invocation.kind == "dynamic":
                unresolved_fidelity = (
                    "bytecode-lambda-target-unresolved"
                    if invocation.fidelity == "bytecode-lambda-metafactory"
                    else invocation.fidelity
                )
            target = self._external_method_node(invocation)
            result.nodes.setdefault(
                target,
                self._method_reference_attributes(
                    invocation,
                    "jvm-bytecode-external-method",
                ),
            )
            self._relationship(
                result,
                source,
                target,
                "bytecode-invoke-unresolved",
                repository_id,
                file_path,
                unresolved_fidelity,
                0.35 if invocation.kind == "dynamic" else 0.4,
                invocation.offset,
                invocation.kind,
                invocation.bootstrap_method,
            )
            result.summary.unresolved_invokes += 1
            return
        result.summary.ambiguous_invokes += 1
        ambiguous_fidelity = (
            "bytecode-lambda-target-ambiguous"
            if invocation.kind == "dynamic"
            else "classpath-owner-ambiguous"
        )
        for provider in targets:
            candidate = self._method_node(
                provider.artifact_node,
                invocation.owner,
                invocation.name,
                invocation.descriptor,
            )
            result.nodes.setdefault(
                candidate,
                self._method_reference_attributes(
                    invocation,
                    "jvm-bytecode-method-reference",
                ),
            )
            self._relationship(
                result,
                source,
                candidate,
                "bytecode-invoke-candidate",
                repository_id,
                file_path,
                ambiguous_fidelity,
                0.5,
                invocation.offset,
                invocation.kind,
                invocation.bootstrap_method,
            )

    def _emit_virtual_invocation(
        self,
        result: JvmBytecodeBundle,
        source: str,
        invocation: _Invocation,
        loaded: list[_LoadedClass],
        providers: dict[str, list[_LoadedClass]],
        defined_methods: dict[tuple[str, str, str, str], str],
        instantiated_types: set[str],
        repository_id: str,
        file_path: str,
    ) -> None:
        result.summary.virtual_invokes += 1
        candidates: set[str] = set()
        rta_candidates: set[str] = set()
        for runtime_class in loaded:
            if not self._concrete_class(runtime_class.fact):
                continue
            if not self._is_subtype(
                runtime_class,
                invocation.owner,
                providers,
                set(),
            ):
                continue
            resolved = self._resolve_virtual_method(
                runtime_class,
                invocation.name,
                invocation.descriptor,
                providers,
                defined_methods,
                set(),
            )
            candidates.update(resolved)
            if runtime_class.fact.internal_name in instantiated_types:
                rta_candidates.update(resolved)
        if rta_candidates:
            for target in sorted(rta_candidates):
                self._relationship(
                    result,
                    source,
                    target,
                    "bytecode-rta-invoke",
                    repository_id,
                    file_path,
                    "bytecode-rta-allocation",
                    0.96,
                    invocation.offset,
                    invocation.kind,
                )
            result.summary.rta_invokes += 1
            result.summary.rta_targets += len(rta_candidates)
        if len(candidates) == 1:
            target = next(iter(candidates))
            self._relationship(
                result,
                source,
                target,
                "bytecode-invoke",
                repository_id,
                file_path,
                "bytecode-cha-single-target",
                0.92,
                invocation.offset,
                invocation.kind,
            )
            result.summary.virtual_single_target += 1
            return
        if candidates:
            for target in sorted(candidates):
                self._relationship(
                    result,
                    source,
                    target,
                    "bytecode-invoke-candidate",
                    repository_id,
                    file_path,
                    "bytecode-cha-candidate",
                    0.65,
                    invocation.offset,
                    invocation.kind,
                )
            result.summary.virtual_ambiguous += 1
            result.summary.ambiguous_invokes += 1
            return
        target = self._external_method_node(invocation)
        result.nodes.setdefault(
            target,
            self._method_reference_attributes(
                invocation,
                "jvm-bytecode-external-method",
            ),
        )
        self._relationship(
            result,
            source,
            target,
            "bytecode-invoke-unresolved",
            repository_id,
            file_path,
            "bytecode-cha-target-unresolved",
            0.35,
            invocation.offset,
            invocation.kind,
        )
        result.summary.unresolved_invokes += 1

    def _resolve_virtual_method(
        self,
        item: _LoadedClass,
        name: str,
        descriptor: str,
        providers: dict[str, list[_LoadedClass]],
        defined_methods: dict[tuple[str, str, str, str], str],
        visited: set[tuple[str, str]],
    ) -> set[str]:
        identity = (item.artifact_node, item.fact.internal_name)
        if identity in visited:
            return set()
        visited = {*visited, identity}
        matching = [
            method
            for method in item.fact.methods
            if method.name == name and method.descriptor == descriptor
        ]
        if matching:
            method = matching[0]
            if method.access_flags & (0x0008 | 0x0400):
                return set()
            target = defined_methods.get(
                (
                    item.artifact_node,
                    item.fact.internal_name,
                    name,
                    descriptor,
                )
            )
            return {target} if target else set()
        inherited: set[str] = set()
        if item.fact.super_name:
            for parent in providers.get(item.fact.super_name, []):
                inherited.update(
                    self._resolve_virtual_method(
                        parent,
                        name,
                        descriptor,
                        providers,
                        defined_methods,
                        visited,
                    )
                )
        if inherited:
            return inherited
        defaults: set[str] = set()
        for interface in item.fact.interfaces:
            for parent in providers.get(interface, []):
                defaults.update(
                    self._resolve_interface_default(
                        parent,
                        name,
                        descriptor,
                        providers,
                        defined_methods,
                        visited,
                    )
                )
        return defaults

    def _resolve_interface_default(
        self,
        item: _LoadedClass,
        name: str,
        descriptor: str,
        providers: dict[str, list[_LoadedClass]],
        defined_methods: dict[tuple[str, str, str, str], str],
        visited: set[tuple[str, str]],
    ) -> set[str]:
        identity = (item.artifact_node, item.fact.internal_name)
        if identity in visited:
            return set()
        visited = {*visited, identity}
        matching = [
            method
            for method in item.fact.methods
            if method.name == name and method.descriptor == descriptor
        ]
        if matching:
            method = matching[0]
            if method.access_flags & (0x0008 | 0x0400):
                return set()
            target = defined_methods.get(
                (
                    item.artifact_node,
                    item.fact.internal_name,
                    name,
                    descriptor,
                )
            )
            return {target} if target else set()
        targets: set[str] = set()
        for interface in item.fact.interfaces:
            for parent in providers.get(interface, []):
                targets.update(
                    self._resolve_interface_default(
                        parent,
                        name,
                        descriptor,
                        providers,
                        defined_methods,
                        visited,
                    )
                )
        return targets

    def _is_subtype(
        self,
        item: _LoadedClass,
        expected_owner: str,
        providers: dict[str, list[_LoadedClass]],
        visited: set[tuple[str, str]],
    ) -> bool:
        if item.fact.internal_name == expected_owner:
            return True
        identity = (item.artifact_node, item.fact.internal_name)
        if identity in visited:
            return False
        visited = {*visited, identity}
        parents = [item.fact.super_name, *item.fact.interfaces]
        if expected_owner in parents:
            return True
        return any(
            self._is_subtype(parent, expected_owner, providers, visited)
            for name in parents
            if name
            for parent in providers.get(name, [])
        )

    @staticmethod
    def _concrete_class(fact: _ClassFact) -> bool:
        return not fact.access_flags & (0x0200 | 0x0400)

    @staticmethod
    def _method_reference_attributes(
        invocation: _Invocation,
        kind: str,
    ) -> dict[str, str | int | bool]:
        return {
            "kind": kind,
            "owner": invocation.owner,
            "method_name": invocation.name,
            "descriptor": invocation.descriptor,
            "dispatch": invocation.kind,
            "bootstrap_method": invocation.bootstrap_method,
        }

    def link_source_calls(
        self,
        file_asts: list[FileAST],
        bytecode_nodes: dict[str, dict[str, str | int | bool]],
        relationships: list[SemanticRelationship],
    ) -> tuple[list[SemanticRelationship], int, int]:
        """Resolve source calls only inside their exact compiler classpath.

        A source file must have build-derived module membership and that module
        must load the bytecode artifact. Owner, arity, and known argument types
        then select a unique best method. Ties are counted but never guessed.
        """

        file_modules = {
            relationship.source: relationship.target
            for relationship in relationships
            if relationship.kind == "member-of-module"
        }
        module_artifacts: dict[str, set[str]] = {}
        for relationship in relationships:
            if relationship.kind != "loads-jvm-artifact":
                continue
            module_artifacts.setdefault(relationship.source, set()).add(relationship.target)
        methods = [
            (node_id, attributes)
            for node_id, attributes in bytecode_nodes.items()
            if attributes.get("kind") == "jvm-bytecode-method"
        ]
        emitted: list[SemanticRelationship] = []
        resolved = 0
        ambiguous = 0
        for ast in file_asts:
            if ast.language.value not in {"java", "kotlin"}:
                continue
            file_id = f"repo:{ast.repository_id}:file:{ast.module_path}"
            module = file_modules.get(file_id)
            allowed_artifacts = module_artifacts.get(module or "", set())
            if not allowed_artifacts:
                continue
            imports = self._import_aliases(ast)
            for call in ast.calls:
                caller = call.caller_symbol_id or call.in_function
                if not caller:
                    continue
                receiver = call.receiver_type or call.receiver or ""
                expected_owner = imports.get(receiver, receiver)
                candidates: list[tuple[int, str]] = []
                for node_id, attributes in methods:
                    if str(attributes.get("artifact_node", "")) not in allowed_artifacts:
                        continue
                    if str(attributes.get("method_name", "")) != call.callee:
                        continue
                    parameters = self._descriptor_parameters(str(attributes.get("descriptor", "")))
                    if parameters is None or len(parameters) != len(call.arguments):
                        continue
                    owner = str(attributes.get("owner", ""))
                    owner_score = self._owner_score(expected_owner, owner)
                    if expected_owner and owner_score < 0:
                        continue
                    score = max(owner_score, 0) + 4
                    compatible = True
                    for actual, expected in zip(call.argument_types, parameters):
                        if not actual:
                            continue
                        match = type_compatibility(actual, expected)
                        if match < 0:
                            compatible = False
                            break
                        score += match
                    if compatible:
                        candidates.append((score, node_id))
                if not candidates:
                    continue
                best_score = max(score for score, _ in candidates)
                winners = sorted(node_id for score, node_id in candidates if score == best_score)
                if len(winners) != 1:
                    ambiguous += 1
                    continue
                emitted.append(
                    SemanticRelationship(
                        source=str(caller),
                        target=winners[0],
                        kind="source-bytecode-call",
                        repository_id=ast.repository_id,
                        file_path=ast.module_path or call.file_path,
                        line=call.line,
                        confidence=0.96,
                        provider="codeguard-jvm-bytecode",
                        fidelity="compiler-classpath-bytecode-signature",
                    )
                )
                resolved += 1
        return emitted, resolved, ambiguous

    @staticmethod
    def _import_aliases(ast: FileAST) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for item in ast.imports:
            imported = item.module.removeprefix("static ").strip()
            if imported.endswith(".*"):
                continue
            simple = item.alias or imported.rsplit(".", 1)[-1]
            aliases[simple] = imported
        return aliases

    @staticmethod
    def _owner_score(expected: str, internal_owner: str) -> int:
        if not expected:
            return 0
        normalized_expected = re.sub(r"<.*>", "", expected).strip()
        normalized_expected = normalized_expected.replace("$", ".")
        normalized_owner = internal_owner.replace("/", ".").replace("$", ".")
        if normalized_expected == normalized_owner:
            return 12
        if normalized_expected.rsplit(".", 1)[-1] == normalized_owner.rsplit(".", 1)[-1]:
            return 8
        return -1

    @staticmethod
    def _descriptor_parameters(descriptor: str) -> list[str] | None:
        if not descriptor.startswith("("):
            return None
        parameters: list[str] = []
        index = 1
        primitives = {
            "Z": "boolean",
            "B": "byte",
            "C": "char",
            "D": "double",
            "F": "float",
            "I": "int",
            "J": "long",
            "S": "short",
        }
        while index < len(descriptor) and descriptor[index] != ")":
            dimensions = 0
            while index < len(descriptor) and descriptor[index] == "[":
                dimensions += 1
                index += 1
            if index >= len(descriptor):
                return None
            token = descriptor[index]
            if token == "L":
                end = descriptor.find(";", index)
                if end < 0:
                    return None
                value = descriptor[index + 1 : end].replace("/", ".")
                index = end + 1
            elif token in primitives:
                value = primitives[token]
                index += 1
            else:
                return None
            parameters.append(value + "[]" * dimensions)
        if index >= len(descriptor) or descriptor[index] != ")":
            return None
        return parameters

    def _emit_hierarchy(
        self,
        result: JvmBytecodeBundle,
        item: _LoadedClass,
        providers: dict[str, list[_LoadedClass]],
        repository_id: str,
    ) -> None:
        if item.fact.super_name:
            self._relationship(
                result,
                item.class_node,
                self._type_target(item.fact.super_name, providers, result),
                "bytecode-extends",
                repository_id,
                item.jar_path,
                "sha256-verified-bytecode",
                1.0,
            )
        for interface in item.fact.interfaces:
            self._relationship(
                result,
                item.class_node,
                self._type_target(interface, providers, result),
                "bytecode-implements",
                repository_id,
                item.jar_path,
                "sha256-verified-bytecode",
                1.0,
            )

    def _type_target(
        self,
        internal_name: str,
        providers: dict[str, list[_LoadedClass]],
        result: JvmBytecodeBundle,
    ) -> str:
        matches = providers.get(internal_name, [])
        if len(matches) == 1:
            return matches[0].class_node
        target = f"jvm-bytecode-external-type:{quote(internal_name, safe='')}"
        result.nodes.setdefault(
            target,
            {"kind": "jvm-bytecode-external-type", "internal_name": internal_name},
        )
        return target

    @staticmethod
    def _selected_classes(
        archive: zipfile.ZipFile,
        target_java: int,
        result: JvmBytecodeBundle,
    ) -> list[zipfile.ZipInfo]:
        selected: dict[str, tuple[int, zipfile.ZipInfo]] = {}
        for info in archive.infolist():
            path = PurePosixPath(info.filename)
            if path.is_absolute() or ".." in path.parts:
                result.summary.warnings.append(f"rejected unsafe JAR member path: {info.filename}")
                continue
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                result.summary.warnings.append(
                    f"rejected symbolic-link JAR member: {info.filename}"
                )
                continue
            if not info.filename.endswith(".class"):
                continue
            logical = info.filename
            version = 0
            match = re.fullmatch(r"META-INF/versions/(\d+)/(.*\.class)", info.filename)
            if match:
                version = int(match.group(1))
                logical = match.group(2)
                if version > target_java:
                    continue
            if logical in {"module-info.class", "package-info.class"}:
                continue
            current = selected.get(logical)
            if current is None or version > current[0]:
                selected[logical] = (version, info)
        return [item[1] for _, item in sorted(selected.items())]

    @staticmethod
    def _infer_coordinate(jar: Path) -> JvmArtifactCoordinate | None:
        try:
            with zipfile.ZipFile(jar) as archive:
                candidates = sorted(
                    (
                        info
                        for info in archive.infolist()
                        if re.fullmatch(
                            r"META-INF/maven/[^/]+/[^/]+/pom\.properties",
                            info.filename,
                        )
                        and info.file_size <= 65_536
                    ),
                    key=lambda info: info.filename,
                )
                if len(candidates) != 1:
                    return None
                values: dict[str, str] = {}
                for line in (
                    archive.read(candidates[0]).decode("utf-8", errors="replace").splitlines()
                ):
                    if "=" in line and not line.lstrip().startswith("#"):
                        key, value = line.split("=", 1)
                        values[key.strip()] = value.strip()
                group = values.get("groupId", "")
                artifact = values.get("artifactId", "")
                version = values.get("version", "")
                if all((group, artifact, version)):
                    return JvmArtifactCoordinate("maven", group, artifact, version)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return None
        return None

    @staticmethod
    def _module_id(repository_id: str, build_root: str, module: str) -> str:
        root_key = "root" if build_root in {"", ".", "root"} else build_root
        module_key = "root" if module in {"", ".", "root"} else module
        return f"repo:{repository_id}:jvm-module:{root_key}:{module_key}"

    @staticmethod
    def _class_node(artifact_node: str, internal_name: str) -> str:
        return f"{artifact_node}::bytecode-class:{quote(internal_name, safe='')}"

    @staticmethod
    def _method_node(
        artifact_node: str,
        owner: str,
        name: str,
        descriptor: str,
    ) -> str:
        signature = quote(f"{owner}#{name}{descriptor}", safe="")
        return f"{artifact_node}::bytecode-method:{signature}"

    @staticmethod
    def _external_method_node(invocation: _Invocation) -> str:
        signature = quote(
            f"{invocation.owner}#{invocation.name}{invocation.descriptor}",
            safe="",
        )
        return f"jvm-bytecode-external-method:{signature}"

    @staticmethod
    def _relationship(
        result: JvmBytecodeBundle,
        source: str,
        target: str,
        kind: str,
        repository_id: str,
        file_path: str,
        fidelity: str,
        confidence: float,
        bytecode_offset: int = -1,
        dispatch: str = "",
        bootstrap_method: str = "",
    ) -> None:
        result.relationships.append(
            SemanticRelationship(
                source=source,
                target=target,
                kind=kind,
                repository_id=repository_id,
                file_path=file_path,
                bytecode_offset=bytecode_offset,
                dispatch=dispatch,
                bootstrap_method=bootstrap_method,
                confidence=confidence,
                provider="codeguard-jvm-bytecode",
                fidelity=fidelity,
            )
        )
