"""Compiler classpath snapshot and bounded JVM bytecode evidence tests."""

import hashlib
import json
import struct
import zipfile
from pathlib import Path

import pytest

from codeguard.config import CodeGuardConfig
from codeguard.ir.query import ProgramGraphQuery
from codeguard.models import (
    CallSite,
    FileAST,
    ImportInfo,
    Language,
    SemanticRelationship,
)
from codeguard.scanner.engine import ScanEngine
from codeguard.scanner.workspace import JvmClasspathArtifact, WorkspaceRepository
from codeguard.semantic.jvm_bytecode import (
    JvmBytecodeImporter,
    JvmClasspathSnapshotEntry,
)
from codeguard.semantic.jvm_dependencies import JvmArtifactCoordinate


def _u2(value: int) -> bytes:
    return struct.pack(">H", value)


def _u4(value: int) -> bytes:
    return struct.pack(">I", value)


def _utf8(value: str) -> bytes:
    encoded = value.encode()
    return b"\x01" + _u2(len(encoded)) + encoded


def _class(index: int) -> bytes:
    return b"\x07" + _u2(index)


def _string(index: int) -> bytes:
    return b"\x08" + _u2(index)


def _integer(value: int) -> bytes:
    return b"\x03" + _u4(value)


def _name_and_type(name: int, descriptor: int) -> bytes:
    return b"\x0c" + _u2(name) + _u2(descriptor)


def _method_ref(owner: int, name_and_type: int) -> bytes:
    return b"\x0a" + _u2(owner) + _u2(name_and_type)


def _interface_method_ref(owner: int, name_and_type: int) -> bytes:
    return b"\x0b" + _u2(owner) + _u2(name_and_type)


def _method_handle(reference_kind: int, reference: int) -> bytes:
    return b"\x0f" + bytes([reference_kind]) + _u2(reference)


def _method_type(descriptor: int) -> bytes:
    return b"\x10" + _u2(descriptor)


def _invoke_dynamic(bootstrap: int, name_and_type: int) -> bytes:
    return b"\x12" + _u2(bootstrap) + _u2(name_and_type)


def _client_class() -> bytes:
    """Build a deterministic Java 17 class with invoke + Exceptions evidence."""
    constant_pool = [
        _utf8("com/acme/Client"),  # 1
        _class(1),  # 2
        _utf8("java/lang/Object"),  # 3
        _class(3),  # 4
        _utf8("call"),  # 5
        _utf8("()V"),  # 6
        _utf8("Code"),  # 7
        _utf8("java/io/IOException"),  # 8
        _class(8),  # 9
        _utf8("Exceptions"),  # 10
        _utf8("com/acme/Library"),  # 11
        _class(11),  # 12
        _utf8("danger"),  # 13
        _utf8("()V"),  # 14
        _name_and_type(13, 14),  # 15
        _method_ref(12, 15),  # 16
    ]
    code = b"\xb8\x00\x10\xb1"  # invokestatic #16; return
    code_attribute = _u2(7) + _u4(16) + _u2(0) + _u2(0) + _u4(4) + code + _u2(0) + _u2(0)
    exceptions_attribute = _u2(10) + _u4(4) + _u2(1) + _u2(9)
    method = _u2(0x0009) + _u2(5) + _u2(6) + _u2(2) + code_attribute + exceptions_attribute
    return (
        b"\xca\xfe\xba\xbe"
        + _u2(0)
        + _u2(61)
        + _u2(len(constant_pool) + 1)
        + b"".join(constant_pool)
        + _u2(0x0021)
        + _u2(2)
        + _u2(4)
        + _u2(0)
        + _u2(0)
        + _u2(1)
        + method
        + _u2(0)
    )


def _library_class() -> bytes:
    constant_pool = [
        _utf8("com/acme/Library"),
        _class(1),
        _utf8("java/lang/Object"),
        _class(3),
        _utf8("danger"),
        _utf8("()V"),
    ]
    method = _u2(0x0109) + _u2(5) + _u2(6) + _u2(0)  # public static native
    return (
        b"\xca\xfe\xba\xbe"
        + _u2(0)
        + _u2(61)
        + _u2(len(constant_pool) + 1)
        + b"".join(constant_pool)
        + _u2(0x0021)
        + _u2(2)
        + _u2(4)
        + _u2(0)
        + _u2(0)
        + _u2(1)
        + method
        + _u2(0)
    )


def _lambda_client_class(
    *,
    alternate: bool = False,
    bootstrap_index: int = 0,
    method_reference: bool = False,
) -> bytes:
    bootstrap_descriptor = (
        "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
        "Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)"
        "Ljava/lang/invoke/CallSite;"
        if alternate
        else "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
        "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;"
        "Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
        "Ljava/lang/invoke/CallSite;"
    )
    constant_pool = [
        _utf8("com/acme/LambdaClient"),  # 1
        _class(1),  # 2
        _utf8("java/lang/Object"),  # 3
        _class(3),  # 4
        _utf8("call"),  # 5
        _utf8("()V"),  # 6
        _utf8("Code"),  # 7
        _utf8("run"),  # 8
        _utf8(
            "(Lcom/acme/LambdaTarget;)Ljava/lang/Runnable;"
            if method_reference
            else "()Ljava/lang/Runnable;"
        ),  # 9
        _name_and_type(8, 9),  # 10
        _invoke_dynamic(bootstrap_index, 10),  # 11
        _utf8("BootstrapMethods"),  # 12
        _utf8("java/lang/invoke/LambdaMetafactory"),  # 13
        _class(13),  # 14
        _utf8("altMetafactory" if alternate else "metafactory"),  # 15
        _utf8(bootstrap_descriptor),  # 16
        _name_and_type(15, 16),  # 17
        _method_ref(14, 17),  # 18
        _method_handle(6, 18),  # 19
        _utf8("()V"),  # 20
        _method_type(20),  # 21
        _utf8("com/acme/LambdaTarget"),  # 22
        _class(22),  # 23
        _utf8("run" if method_reference else "lambda$call$0"),  # 24
        _name_and_type(24, 20),  # 25
        _method_ref(23, 25),  # 26
        _method_handle(5 if method_reference else 6, 26),  # 27
    ]
    if alternate:
        constant_pool.append(_integer(0))  # 28: no marker/bridge flags
    code = (b"\x01" if method_reference else b"") + b"\xba\x00\x0b\x00\x00\x57\xb1"
    code_attribute = (
        _u2(7) + _u4(12 + len(code)) + _u2(1) + _u2(0) + _u4(len(code)) + code + _u2(0) + _u2(0)
    )
    method = _u2(0x0009) + _u2(5) + _u2(6) + _u2(1) + code_attribute
    bootstrap_arguments = (21, 27, 21, 28) if alternate else (21, 27, 21)
    bootstrap_payload = (
        _u2(1)
        + _u2(19)
        + _u2(len(bootstrap_arguments))
        + b"".join(_u2(index) for index in bootstrap_arguments)
    )
    bootstrap_attribute = _u2(12) + _u4(len(bootstrap_payload)) + bootstrap_payload
    return (
        b"\xca\xfe\xba\xbe"
        + _u2(0)
        + _u2(61)
        + _u2(len(constant_pool) + 1)
        + b"".join(constant_pool)
        + _u2(0x0021)
        + _u2(2)
        + _u2(4)
        + _u2(0)
        + _u2(0)
        + _u2(1)
        + method
        + _u2(1)
        + bootstrap_attribute
    )


def _lambda_target_class(*, method_reference: bool = False) -> bytes:
    constant_pool = [
        _utf8("com/acme/LambdaTarget"),
        _class(1),
        _utf8("java/lang/Object"),
        _class(3),
        _utf8("run" if method_reference else "lambda$call$0"),
        _utf8("()V"),
    ]
    method_access = 0x0101 if method_reference else 0x0109
    method = _u2(method_access) + _u2(5) + _u2(6) + _u2(0)
    return (
        b"\xca\xfe\xba\xbe"
        + _u2(0)
        + _u2(61)
        + _u2(len(constant_pool) + 1)
        + b"".join(constant_pool)
        + _u2(0x0021)
        + _u2(2)
        + _u2(4)
        + _u2(0)
        + _u2(0)
        + _u2(1)
        + method
        + _u2(0)
    )


def _string_concat_client_class() -> bytes:
    bootstrap_descriptor = (
        "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
        "Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)"
        "Ljava/lang/invoke/CallSite;"
    )
    constant_pool = [
        _utf8("com/acme/ConcatClient"),  # 1
        _class(1),  # 2
        _utf8("java/lang/Object"),  # 3
        _class(3),  # 4
        _utf8("call"),  # 5
        _utf8("()V"),  # 6
        _utf8("Code"),  # 7
        _utf8("makeConcatWithConstants"),  # 8
        _utf8("(Ljava/lang/String;)Ljava/lang/String;"),  # 9
        _name_and_type(8, 9),  # 10
        _invoke_dynamic(0, 10),  # 11
        _utf8("BootstrapMethods"),  # 12
        _utf8("java/lang/invoke/StringConcatFactory"),  # 13
        _class(13),  # 14
        _utf8("makeConcatWithConstants"),  # 15
        _utf8(bootstrap_descriptor),  # 16
        _name_and_type(15, 16),  # 17
        _method_ref(14, 17),  # 18
        _method_handle(6, 18),  # 19
        _utf8("\u0001!"),  # 20
        _string(20),  # 21
    ]
    code = b"\x12\x15\xba\x00\x0b\x00\x00\x57\xb1"
    code_attribute = (
        _u2(7) + _u4(12 + len(code)) + _u2(1) + _u2(0) + _u4(len(code)) + code + _u2(0) + _u2(0)
    )
    method = _u2(0x0009) + _u2(5) + _u2(6) + _u2(1) + code_attribute
    bootstrap_payload = _u2(1) + _u2(19) + _u2(1) + _u2(21)
    bootstrap_attribute = _u2(12) + _u4(len(bootstrap_payload)) + bootstrap_payload
    return (
        b"\xca\xfe\xba\xbe"
        + _u2(0)
        + _u2(61)
        + _u2(len(constant_pool) + 1)
        + b"".join(constant_pool)
        + _u2(0x0021)
        + _u2(2)
        + _u2(4)
        + _u2(0)
        + _u2(0)
        + _u2(1)
        + method
        + _u2(1)
        + bootstrap_attribute
    )


def _service_interface(default_method: bool = False) -> bytes:
    constant_pool = [
        _utf8("com/acme/Service"),
        _class(1),
        _utf8("java/lang/Object"),
        _class(3),
        _utf8("run"),
        _utf8("()V"),
    ]
    if default_method:
        constant_pool.append(_utf8("Code"))
        code_attribute = _u2(7) + _u4(13) + _u2(0) + _u2(1) + _u4(1) + b"\xb1" + _u2(0) + _u2(0)
        method = _u2(0x0001) + _u2(5) + _u2(6) + _u2(1) + code_attribute
    else:
        method = _u2(0x0401) + _u2(5) + _u2(6) + _u2(0)
    return (
        b"\xca\xfe\xba\xbe"
        + _u2(0)
        + _u2(61)
        + _u2(len(constant_pool) + 1)
        + b"".join(constant_pool)
        + _u2(0x0601)
        + _u2(2)
        + _u2(4)
        + _u2(0)
        + _u2(0)
        + _u2(1)
        + method
        + _u2(0)
    )


def _service_implementation(name: str) -> bytes:
    constant_pool = [
        _utf8(name),
        _class(1),
        _utf8("java/lang/Object"),
        _class(3),
        _utf8("com/acme/Service"),
        _class(5),
        _utf8("run"),
        _utf8("()V"),
    ]
    method = _u2(0x0101) + _u2(7) + _u2(8) + _u2(0)
    return (
        b"\xca\xfe\xba\xbe"
        + _u2(0)
        + _u2(61)
        + _u2(len(constant_pool) + 1)
        + b"".join(constant_pool)
        + _u2(0x0021)
        + _u2(2)
        + _u2(4)
        + _u2(1)
        + _u2(6)
        + _u2(0)
        + _u2(1)
        + method
        + _u2(0)
    )


def _service_subclass(name: str, parent: str) -> bytes:
    constant_pool = [
        _utf8(name),
        _class(1),
        _utf8(parent),
        _class(3),
    ]
    return (
        b"\xca\xfe\xba\xbe"
        + _u2(0)
        + _u2(61)
        + _u2(len(constant_pool) + 1)
        + b"".join(constant_pool)
        + _u2(0x0021)
        + _u2(2)
        + _u2(4)
        + _u2(0)
        + _u2(0)
        + _u2(0)
        + _u2(0)
    )


def _service_implementor_without_override(name: str) -> bytes:
    constant_pool = [
        _utf8(name),
        _class(1),
        _utf8("java/lang/Object"),
        _class(3),
        _utf8("com/acme/Service"),
        _class(5),
    ]
    return (
        b"\xca\xfe\xba\xbe"
        + _u2(0)
        + _u2(61)
        + _u2(len(constant_pool) + 1)
        + b"".join(constant_pool)
        + _u2(0x0021)
        + _u2(2)
        + _u2(4)
        + _u2(1)
        + _u2(6)
        + _u2(0)
        + _u2(0)
        + _u2(0)
    )


def _virtual_client_class(allocations: tuple[str, ...] = ()) -> bytes:
    constant_pool = [
        _utf8("com/acme/Client"),  # 1
        _class(1),  # 2
        _utf8("java/lang/Object"),  # 3
        _class(3),  # 4
        _utf8("call"),  # 5
        _utf8("()V"),  # 6
        _utf8("Code"),  # 7
        _utf8("com/acme/Service"),  # 8
        _class(8),  # 9
        _utf8("run"),  # 10
        _utf8("()V"),  # 11
        _name_and_type(10, 11),  # 12
        _interface_method_ref(9, 12),  # 13
    ]
    allocation_class_indices: list[int] = []
    for allocation in allocations:
        utf8_index = len(constant_pool) + 1
        constant_pool.append(_utf8(allocation))
        class_index = len(constant_pool) + 1
        constant_pool.append(_class(utf8_index))
        allocation_class_indices.append(class_index)
    code = (
        b"".join(b"\xbb" + _u2(index) + b"\x57" for index in allocation_class_indices)
        + b"\x01\xb9\x00\x0d\x01\x00\xb1"
    )
    code_attribute = (
        _u2(7) + _u4(12 + len(code)) + _u2(2) + _u2(0) + _u4(len(code)) + code + _u2(0) + _u2(0)
    )
    method = _u2(0x0009) + _u2(5) + _u2(6) + _u2(1) + code_attribute
    return (
        b"\xca\xfe\xba\xbe"
        + _u2(0)
        + _u2(61)
        + _u2(len(constant_pool) + 1)
        + b"".join(constant_pool)
        + _u2(0x0021)
        + _u2(2)
        + _u2(4)
        + _u2(0)
        + _u2(0)
        + _u2(1)
        + method
        + _u2(0)
    )


def _write_virtual_snapshot(
    root: Path,
    implementations: tuple[str, ...],
    subclasses: tuple[tuple[str, str], ...] = (),
    passive_implementations: tuple[str, ...] = (),
    default_interface: bool = False,
    allocations: tuple[str, ...] = (),
) -> Path:
    jar = root / "virtual.jar"
    with zipfile.ZipFile(jar, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("com/acme/Client.class", _virtual_client_class(allocations))
        archive.writestr(
            "com/acme/Service.class",
            _service_interface(default_method=default_interface),
        )
        for implementation in implementations:
            archive.writestr(
                f"{implementation}.class",
                _service_implementation(implementation),
            )
        for subclass, parent in subclasses:
            archive.writestr(
                f"{subclass}.class",
                _service_subclass(subclass, parent),
            )
        for implementation in passive_implementations:
            archive.writestr(
                f"{implementation}.class",
                _service_implementor_without_override(implementation),
            )
    digest = hashlib.sha256(jar.read_bytes()).hexdigest()
    snapshot = root / "classpath.json"
    snapshot.write_text(
        json.dumps(
            {
                "contract_version": 1,
                "repository_id": "app",
                "producer": {"name": "test", "version": "1"},
                "target_java": 17,
                "entries": [
                    {
                        "path": "virtual.jar",
                        "sha256": digest,
                        "scope": "compile",
                        "build_root": "root",
                        "module": "root",
                        "coordinate": {
                            "manager": "maven",
                            "group": "com.acme",
                            "artifact": "virtual",
                            "version": "1.0.0",
                        },
                    }
                ],
            }
        )
    )
    return snapshot


def _write_snapshot(root: Path, *, valid_hash: bool = True) -> tuple[Path, Path]:
    jar = root / "client.jar"
    with zipfile.ZipFile(jar, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("com/acme/Client.class", _client_class())
        archive.writestr("com/acme/Library.class", _library_class())
    digest = hashlib.sha256(jar.read_bytes()).hexdigest()
    snapshot = root / "classpath.json"
    snapshot.write_text(
        json.dumps(
            {
                "contract_version": 1,
                "repository_id": "app",
                "producer": {"name": "gradle", "version": "8.14"},
                "target_java": 17,
                "entries": [
                    {
                        "path": "client.jar",
                        "sha256": digest if valid_hash else "0" * 64,
                        "scope": "compile",
                        "build_root": "root",
                        "module": "root",
                        "coordinate": {
                            "manager": "maven",
                            "group": "com.acme",
                            "artifact": "client",
                            "version": "1.0.0",
                        },
                    }
                ],
            }
        )
    )
    return snapshot, jar


def _write_invokedynamic_snapshot(
    root: Path,
    *,
    concat: bool = False,
    alternate: bool = False,
    bootstrap_index: int = 0,
    method_reference: bool = False,
) -> Path:
    jar = root / "invokedynamic.jar"
    with zipfile.ZipFile(jar, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if concat:
            archive.writestr("com/acme/ConcatClient.class", _string_concat_client_class())
        else:
            archive.writestr(
                "com/acme/LambdaClient.class",
                _lambda_client_class(
                    alternate=alternate,
                    bootstrap_index=bootstrap_index,
                    method_reference=method_reference,
                ),
            )
            archive.writestr(
                "com/acme/LambdaTarget.class",
                _lambda_target_class(method_reference=method_reference),
            )
    digest = hashlib.sha256(jar.read_bytes()).hexdigest()
    snapshot = root / "classpath-invokedynamic.json"
    snapshot.write_text(
        json.dumps(
            {
                "contract_version": 1,
                "repository_id": "app",
                "producer": {"name": "test", "version": "1"},
                "target_java": 17,
                "entries": [
                    {
                        "path": "invokedynamic.jar",
                        "sha256": digest,
                        "scope": "compile",
                        "build_root": "root",
                        "module": "root",
                        "coordinate": {
                            "manager": "maven",
                            "group": "com.acme",
                            "artifact": "invokedynamic",
                            "version": "1.0.0",
                        },
                    }
                ],
            }
        )
    )
    return snapshot


def test_classpath_snapshot_imports_hashed_bytecode_signature_and_calls(
    tmp_path: Path,
):
    repository = tmp_path / "app"
    evidence = tmp_path / "evidence"
    repository.mkdir()
    evidence.mkdir()
    (repository / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>com.example</groupId><artifactId>app</artifactId>"
        "<version>1.0.0</version></project>\n"
    )
    (repository / "App.java").write_text(
        "import com.acme.Client;\n"
        "import java.io.IOException;\n"
        "class App {\n"
        "  void recover() {}\n"
        "  void run() {\n"
        "    try { Client.call(); }\n"
        "    catch (IOException error) { recover(); }\n"
        "  }\n"
        "}\n"
    )
    snapshot, _ = _write_snapshot(evidence)
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\nrepositories:\n"
        "  - id: app\n"
        "    path: ./app\n"
        "    jvm_classpath_snapshots:\n"
        "      - path: ./evidence/classpath.json\n"
    )
    config = CodeGuardConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan_workspace(manifest)

    summary = result.semantic_analysis
    assert summary.jvm_classpath_snapshots == 1
    assert summary.jvm_classpath_entries == 1
    assert summary.jvm_classpath_entries_verified == 1
    assert summary.jvm_classpath_entries_rejected == 0
    assert summary.jvm_bytecode_classes == 2
    assert summary.jvm_bytecode_methods == 2
    assert summary.jvm_bytecode_invokes == 1
    assert summary.jvm_bytecode_declared_exceptions == 1
    assert summary.jvm_bytecode_source_calls_resolved == 1
    assert summary.jvm_bytecode_source_calls_ambiguous == 0
    assert result.program_graph.interprocedural_bytecode_call_edges == 1
    assert result.program_graph.interprocedural_bytecode_return_edges == 1
    assert result.program_graph.interprocedural_bytecode_throw_edges == 1
    artifact = JvmArtifactCoordinate("maven", "com.acme", "client", "1.0.0")
    class_nodes = [
        node
        for node, data in engine._last_program_graph.nodes(data=True)
        if data.get("kind") == "jvm-bytecode-class"
        and data.get("internal_name") == "com/acme/Client"
    ]
    assert len(class_nodes) == 1
    bytecode_methods = {
        data.get("owner"): node
        for node, data in engine._last_program_graph.nodes(data=True)
        if data.get("kind") == "jvm-bytecode-method"
    }
    source = "repo:app:App.java::App.run()"
    assert ProgramGraphQuery(engine._last_program_graph).source_to_sink_paths(
        {source},
        {bytecode_methods["com/acme/Library"]},
    ) == [
        [
            source,
            bytecode_methods["com/acme/Client"],
            bytecode_methods["com/acme/Library"],
        ]
    ]
    assert any(
        target == artifact.node_id and data.get("kind") == "loads-jvm-artifact"
        for _, target, data in engine._last_program_graph.out_edges(
            "repo:app:jvm-module:root:root", data=True
        )
    )
    assert any(
        data.get("kind") == "bytecode-invoke"
        for _, _, data in engine._last_program_graph.edges(data=True)
    )
    assert any(
        data.get("kind") == "bytecode-declares-throws"
        for _, _, data in engine._last_program_graph.edges(data=True)
    )
    assert any(
        data.get("kind") == "source-bytecode-call"
        for _, _, data in engine._last_program_graph.edges(data=True)
    )
    bytecode_icfg = [
        (source, target, data)
        for source, target, data in engine._last_program_graph.edges(data=True)
        if str(data.get("kind", "")).startswith("interprocedural-bytecode-")
    ]
    assert {data["kind"] for _, _, data in bytecode_icfg} == {
        "interprocedural-bytecode-call",
        "interprocedural-bytecode-return",
        "interprocedural-bytecode-throw",
    }
    assert any(
        "catch-entry" in target
        for _, target, data in bytecode_icfg
        if data["kind"] == "interprocedural-bytecode-throw"
    )
    call_edge = next(
        edge for edge in bytecode_icfg if edge[2]["kind"] == "interprocedural-bytecode-call"
    )
    return_edge = next(
        edge for edge in bytecode_icfg if edge[2]["kind"] == "interprocedural-bytecode-return"
    )
    throw_edge = next(
        edge for edge in bytecode_icfg if edge[2]["kind"] == "interprocedural-bytecode-throw"
    )
    query = ProgramGraphQuery(engine._last_program_graph)
    assert query.context_balanced_path(call_edge[0], return_edge[1], {"icfg"}) == [
        call_edge[0],
        call_edge[1],
        return_edge[1],
    ]
    assert query.context_balanced_path(call_edge[0], throw_edge[1], {"icfg"}) == [
        call_edge[0],
        call_edge[1],
        throw_edge[1],
    ]
    assert snapshot.is_file()


def test_classpath_snapshot_rejects_hash_mismatch_without_failing_scan(
    tmp_path: Path,
):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot, _ = _write_snapshot(tmp_path, valid_hash=False)
    artifact = JvmClasspathArtifact(path=snapshot)
    repository = WorkspaceRepository(id="app", path=repository_root)

    imported = JvmBytecodeImporter().load(artifact, repository)

    assert imported.summary.classpath_entries == 1
    assert imported.summary.entries_verified == 0
    assert imported.summary.entries_rejected == 1
    assert imported.summary.bytecode_classes == 0
    assert any("SHA-256 mismatch" in warning for warning in imported.summary.warnings)


def test_lambda_metafactory_invokedynamic_reaches_implementation_method(tmp_path: Path):
    repository = tmp_path / "app"
    evidence = tmp_path / "evidence"
    repository.mkdir()
    evidence.mkdir()
    (repository / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>com.example</groupId><artifactId>app</artifactId>"
        "<version>1.0.0</version></project>\n"
    )
    (repository / "App.java").write_text(
        "import com.acme.LambdaClient;\nclass App { void run() { LambdaClient.call(); } }\n"
    )
    snapshot = _write_invokedynamic_snapshot(evidence)
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\nrepositories:\n"
        "  - id: app\n"
        "    path: ./app\n"
        "    jvm_classpath_snapshots:\n"
        "      - path: ./evidence/classpath-invokedynamic.json\n"
    )
    config = CodeGuardConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan_workspace(manifest)

    methods = {
        data.get("owner"): node
        for node, data in engine._last_program_graph.nodes(data=True)
        if data.get("kind") == "jvm-bytecode-method"
    }
    source = "repo:app:App.java::App.run()"
    sink = methods["com/acme/LambdaTarget"]
    assert ProgramGraphQuery(engine._last_program_graph).source_to_sink_paths(
        {source},
        {sink},
    ) == [[source, methods["com/acme/LambdaClient"], sink]]
    assert result.semantic_analysis.jvm_bytecode_invokedynamic_sites == 1
    assert result.semantic_analysis.jvm_bytecode_lambda_targets == 1
    assert result.semantic_analysis.jvm_bytecode_unresolved_bootstraps == 0
    dynamic_edges = [
        data
        for _, target, data in engine._last_program_graph.edges(data=True)
        if target == sink and data.get("dispatch") == "dynamic"
    ]
    assert len(dynamic_edges) == 1
    assert dynamic_edges[0]["kind"] == "bytecode-invoke"
    assert dynamic_edges[0]["fidelity"] == "bytecode-lambda-metafactory"
    assert dynamic_edges[0]["bytecode_offset"] == 0
    assert dynamic_edges[0]["bootstrap_method"].startswith(
        "java/lang/invoke/LambdaMetafactory#metafactory"
    )
    assert snapshot.is_file()


def test_non_lambda_invokedynamic_is_preserved_as_unresolved_bootstrap(tmp_path: Path):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot = _write_invokedynamic_snapshot(tmp_path, concat=True)

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    dynamic_edges = [
        relationship
        for relationship in imported.relationships
        if relationship.dispatch == "dynamic"
    ]
    assert imported.summary.bytecode_invokes == 1
    assert imported.summary.invokedynamic_sites == 1
    assert imported.summary.lambda_targets == 0
    assert imported.summary.unresolved_bootstraps == 1
    assert imported.summary.unresolved_invokes == 1
    assert len(dynamic_edges) == 1
    assert dynamic_edges[0].kind == "bytecode-invoke-unresolved"
    assert dynamic_edges[0].fidelity == "bytecode-invokedynamic-bootstrap-unresolved"
    assert dynamic_edges[0].bytecode_offset == 2
    assert dynamic_edges[0].bootstrap_method.startswith(
        "java/lang/invoke/StringConcatFactory#makeConcatWithConstants"
    )
    assert imported.nodes[dynamic_edges[0].target]["owner"] == "<dynamic>"


def test_alt_metafactory_invokedynamic_resolves_kotlin_indy_shape(tmp_path: Path):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot = _write_invokedynamic_snapshot(tmp_path, alternate=True)

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    dynamic_edges = [
        relationship
        for relationship in imported.relationships
        if relationship.dispatch == "dynamic"
    ]
    assert imported.summary.invokedynamic_sites == 1
    assert imported.summary.lambda_targets == 1
    assert imported.summary.unresolved_bootstraps == 0
    assert len(dynamic_edges) == 1
    assert imported.nodes[dynamic_edges[0].target]["owner"] == "com/acme/LambdaTarget"
    assert dynamic_edges[0].fidelity == "bytecode-lambda-metafactory"
    assert "#altMetafactory" in dynamic_edges[0].bootstrap_method


def test_invokedynamic_method_reference_resolves_virtual_implementation_handle(
    tmp_path: Path,
):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot = _write_invokedynamic_snapshot(tmp_path, method_reference=True)

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    dynamic_edges = [
        relationship
        for relationship in imported.relationships
        if relationship.dispatch == "dynamic"
    ]
    assert imported.summary.invokedynamic_sites == 1
    assert imported.summary.lambda_targets == 1
    assert len(dynamic_edges) == 1
    target = imported.nodes[dynamic_edges[0].target]
    assert target["owner"] == "com/acme/LambdaTarget"
    assert target["method_name"] == "run"
    assert target["descriptor"] == "()V"
    assert dynamic_edges[0].bytecode_offset == 1
    assert dynamic_edges[0].fidelity == "bytecode-lambda-metafactory"


def test_invokedynamic_rejects_out_of_range_bootstrap_index_without_crashing(
    tmp_path: Path,
):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot = _write_invokedynamic_snapshot(tmp_path, bootstrap_index=1)

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    assert imported.summary.entries_verified == 1
    assert imported.summary.bytecode_classes == 1
    assert imported.summary.invokedynamic_sites == 0
    assert any(
        "invokedynamic bootstrap index out of range: 1" in warning
        for warning in imported.summary.warnings
    )


def test_shared_jar_is_loaded_by_each_module_but_parsed_only_once(tmp_path: Path):
    repository_root = tmp_path / "app"
    evidence = tmp_path / "evidence"
    repository_root.mkdir()
    evidence.mkdir()
    snapshot, _ = _write_snapshot(evidence)
    payload = json.loads(snapshot.read_text())
    payload["entries"][0]["module"] = "api"
    duplicate = dict(payload["entries"][0])
    duplicate["module"] = "batch"
    payload["entries"].append(duplicate)
    snapshot.write_text(json.dumps(payload))

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    assert imported.summary.classpath_entries == 2
    assert imported.summary.entries_verified == 2
    assert imported.summary.bytecode_classes == 2
    assert imported.summary.bytecode_methods == 2
    assert {
        relationship.source
        for relationship in imported.relationships
        if relationship.kind == "loads-jvm-artifact"
    } == {
        "repo:app:jvm-module:root:api",
        "repo:app:jvm-module:root:batch",
    }


def test_interface_dispatch_emits_all_concrete_override_candidates(tmp_path: Path):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot = _write_virtual_snapshot(
        tmp_path,
        ("com/acme/FastService", "com/acme/SafeService"),
    )

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    candidates = [
        relationship
        for relationship in imported.relationships
        if relationship.kind == "bytecode-invoke-candidate"
    ]
    assert imported.summary.bytecode_invokes == 1
    assert imported.summary.virtual_invokes == 1
    assert imported.summary.virtual_single_target == 0
    assert imported.summary.virtual_ambiguous == 1
    assert imported.summary.ambiguous_invokes == 1
    assert imported.summary.allocation_sites == 0
    assert imported.summary.rta_invokes == 0
    assert imported.summary.rta_targets == 0
    assert {imported.nodes[edge.target]["owner"] for edge in candidates} == {
        "com/acme/FastService",
        "com/acme/SafeService",
    }
    assert {edge.dispatch for edge in candidates} == {"interface"}
    assert {edge.fidelity for edge in candidates} == {"bytecode-cha-candidate"}
    assert {edge.bytecode_offset for edge in candidates} == {1}
    assert not any(
        relationship.kind == "bytecode-rta-invoke" for relationship in imported.relationships
    )


def test_interface_rta_narrows_candidates_without_removing_cha_edges(tmp_path: Path):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot = _write_virtual_snapshot(
        tmp_path,
        ("com/acme/FastService", "com/acme/SafeService"),
        allocations=("com/acme/SafeService",),
    )

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    cha = [
        relationship
        for relationship in imported.relationships
        if relationship.kind == "bytecode-invoke-candidate"
    ]
    rta = [
        relationship
        for relationship in imported.relationships
        if relationship.kind == "bytecode-rta-invoke"
    ]
    allocations = [
        relationship
        for relationship in imported.relationships
        if relationship.kind == "bytecode-allocates"
    ]
    assert {imported.nodes[edge.target]["owner"] for edge in cha} == {
        "com/acme/FastService",
        "com/acme/SafeService",
    }
    assert len(rta) == 1
    assert imported.nodes[rta[0].target]["owner"] == "com/acme/SafeService"
    assert rta[0].dispatch == "interface"
    assert rta[0].fidelity == "bytecode-rta-allocation"
    assert rta[0].bytecode_offset == 5
    assert len(allocations) == 1
    assert imported.nodes[allocations[0].target]["internal_name"] == "com/acme/SafeService"
    assert allocations[0].dispatch == "new"
    assert allocations[0].bytecode_offset == 0
    assert imported.summary.allocation_sites == 1
    assert imported.summary.rta_invokes == 1
    assert imported.summary.rta_targets == 1


def test_interface_dispatch_collapses_unique_concrete_target(tmp_path: Path):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot = _write_virtual_snapshot(tmp_path, ("com/acme/OnlyService",))

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    invokes = [
        relationship
        for relationship in imported.relationships
        if relationship.kind == "bytecode-invoke"
    ]
    assert imported.summary.virtual_invokes == 1
    assert imported.summary.virtual_single_target == 1
    assert imported.summary.virtual_ambiguous == 0
    assert len(invokes) == 1
    assert imported.nodes[invokes[0].target]["owner"] == "com/acme/OnlyService"
    assert invokes[0].dispatch == "interface"
    assert invokes[0].fidelity == "bytecode-cha-single-target"


def test_interface_dispatch_deduplicates_inherited_implementation(tmp_path: Path):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot = _write_virtual_snapshot(
        tmp_path,
        ("com/acme/BaseService",),
        (
            ("com/acme/FastService", "com/acme/BaseService"),
            ("com/acme/SafeService", "com/acme/BaseService"),
        ),
    )

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    invokes = [
        relationship
        for relationship in imported.relationships
        if relationship.kind == "bytecode-invoke"
    ]
    assert imported.summary.virtual_single_target == 1
    assert imported.summary.virtual_ambiguous == 0
    assert len(invokes) == 1
    assert imported.nodes[invokes[0].target]["owner"] == "com/acme/BaseService"


def test_interface_rta_resolves_allocated_subclass_to_inherited_method(tmp_path: Path):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot = _write_virtual_snapshot(
        tmp_path,
        ("com/acme/BaseService",),
        (("com/acme/SafeService", "com/acme/BaseService"),),
        allocations=("com/acme/SafeService",),
    )

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    rta = [
        relationship
        for relationship in imported.relationships
        if relationship.kind == "bytecode-rta-invoke"
    ]
    assert len(rta) == 1
    assert imported.nodes[rta[0].target]["owner"] == "com/acme/BaseService"
    assert imported.summary.rta_invokes == 1
    assert imported.summary.rta_targets == 1


def test_interface_rta_preserves_multiple_allocated_targets(tmp_path: Path):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot = _write_virtual_snapshot(
        tmp_path,
        ("com/acme/FastService", "com/acme/SafeService"),
        allocations=("com/acme/FastService", "com/acme/SafeService"),
    )

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    rta = [
        relationship
        for relationship in imported.relationships
        if relationship.kind == "bytecode-rta-invoke"
    ]
    assert {imported.nodes[edge.target]["owner"] for edge in rta} == {
        "com/acme/FastService",
        "com/acme/SafeService",
    }
    assert imported.summary.allocation_sites == 2
    assert imported.summary.rta_invokes == 1
    assert imported.summary.rta_targets == 2


def test_interface_dispatch_resolves_shared_default_method(tmp_path: Path):
    repository_root = tmp_path / "app"
    repository_root.mkdir()
    snapshot = _write_virtual_snapshot(
        tmp_path,
        (),
        passive_implementations=(
            "com/acme/FastService",
            "com/acme/SafeService",
        ),
        default_interface=True,
    )

    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=snapshot),
        WorkspaceRepository(id="app", path=repository_root),
    )

    invokes = [
        relationship
        for relationship in imported.relationships
        if relationship.kind == "bytecode-invoke"
    ]
    assert imported.summary.virtual_single_target == 1
    assert imported.summary.virtual_ambiguous == 0
    assert len(invokes) == 1
    assert imported.nodes[invokes[0].target]["owner"] == "com/acme/Service"


def test_source_to_sink_paths_follow_all_bytecode_interface_candidates(
    tmp_path: Path,
):
    repository = tmp_path / "app"
    evidence = tmp_path / "evidence"
    repository.mkdir()
    evidence.mkdir()
    (repository / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>com.example</groupId><artifactId>app</artifactId>"
        "<version>1.0.0</version></project>\n"
    )
    (repository / "App.java").write_text(
        "import com.acme.Client;\nclass App { void run() { Client.call(); } }\n"
    )
    snapshot = _write_virtual_snapshot(
        evidence,
        ("com/acme/FastService", "com/acme/SafeService"),
        allocations=("com/acme/SafeService",),
    )
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\nrepositories:\n"
        "  - id: app\n"
        "    path: ./app\n"
        "    jvm_classpath_snapshots:\n"
        "      - path: ./evidence/classpath.json\n"
    )
    config = CodeGuardConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan_workspace(manifest)

    methods = {
        data.get("owner"): node
        for node, data in engine._last_program_graph.nodes(data=True)
        if data.get("kind") == "jvm-bytecode-method" and data.get("method_name") in {"call", "run"}
    }
    source = "repo:app:App.java::App.run()"
    sinks = {
        methods["com/acme/FastService"],
        methods["com/acme/SafeService"],
    }
    paths = ProgramGraphQuery(engine._last_program_graph).source_to_sink_paths(
        {source},
        sinks,
    )
    assert result.semantic_analysis.jvm_bytecode_virtual_invokes == 1
    assert result.semantic_analysis.jvm_bytecode_virtual_ambiguous == 1
    assert result.semantic_analysis.jvm_bytecode_allocation_sites == 1
    assert result.semantic_analysis.jvm_bytecode_rta_invokes == 1
    assert result.semantic_analysis.jvm_bytecode_rta_targets == 1
    assert len(paths) == 2
    assert {path[-1] for path in paths} == sinks
    assert all(path[1] == methods["com/acme/Client"] for path in paths)
    assert {
        data.get("dispatch")
        for _, _, data in engine._last_program_graph.edges(data=True)
        if data.get("kind") == "bytecode-invoke-candidate"
    } == {"interface"}
    assert {
        target
        for _, target, data in engine._last_program_graph.edges(data=True)
        if data.get("kind") == "bytecode-rta-invoke"
    } == {methods["com/acme/SafeService"]}
    assert snapshot.is_file()


def test_classpath_entry_rejects_path_escape():
    with pytest.raises(ValueError, match="beneath"):
        JvmClasspathSnapshotEntry.model_validate(
            {
                "path": "../outside.jar",
                "sha256": "0" * 64,
                "coordinate": {
                    "manager": "maven",
                    "group": "com.acme",
                    "artifact": "unsafe",
                    "version": "1.0.0",
                },
            }
        )


def _source_call_ast() -> FileAST:
    return FileAST(
        file_path="/workspace/app/App.java",
        language=Language.JAVA,
        repository_id="app",
        module_path="App.java",
        imports=[ImportInfo(module="com.acme.Client")],
        calls=[
            CallSite(
                callee="call",
                file_path="/workspace/app/App.java",
                line=4,
                column=4,
                receiver="Client",
                caller_symbol_id="repo:app:App.java::App.run()",
                repository_id="app",
            )
        ],
    )


def test_source_bytecode_linker_does_not_guess_between_duplicate_providers():
    ast = _source_call_ast()
    relationships = [
        SemanticRelationship(
            source="repo:app:file:App.java",
            target="repo:app:jvm-module:root:root",
            kind="member-of-module",
        ),
        SemanticRelationship(
            source="repo:app:jvm-module:root:root",
            target="artifact-a",
            kind="loads-jvm-artifact",
        ),
        SemanticRelationship(
            source="repo:app:jvm-module:root:root",
            target="artifact-b",
            kind="loads-jvm-artifact",
        ),
    ]
    nodes = {
        f"method-{suffix}": {
            "kind": "jvm-bytecode-method",
            "artifact_node": f"artifact-{suffix}",
            "owner": "com/acme/Client",
            "method_name": "call",
            "descriptor": "()V",
        }
        for suffix in ("a", "b")
    }

    linked, resolved, ambiguous = JvmBytecodeImporter().link_source_calls(
        [ast], nodes, relationships
    )

    assert linked == []
    assert resolved == 0
    assert ambiguous == 1


def test_source_bytecode_linker_is_confined_to_file_build_module():
    ast = _source_call_ast()
    relationships = [
        SemanticRelationship(
            source="repo:app:file:App.java",
            target="repo:app:jvm-module:root:consumer",
            kind="member-of-module",
        ),
        SemanticRelationship(
            source="repo:app:jvm-module:root:provider",
            target="provider-artifact",
            kind="loads-jvm-artifact",
        ),
    ]
    nodes = {
        "provider-method": {
            "kind": "jvm-bytecode-method",
            "artifact_node": "provider-artifact",
            "owner": "com/acme/Client",
            "method_name": "call",
            "descriptor": "()V",
        }
    }

    linked, resolved, ambiguous = JvmBytecodeImporter().link_source_calls(
        [ast], nodes, relationships
    )

    assert linked == []
    assert resolved == 0
    assert ambiguous == 0
