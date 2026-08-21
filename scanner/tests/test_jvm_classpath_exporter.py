"""Isolated JVM classpath export, bundle, and materialization tests."""

import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

import aegify.harness
from aegify.cli import app
from aegify.config import AegifyConfig
from aegify.harness.docker import DockerVerificationExecutor
from aegify.harness.models import (
    VerificationArtifact,
    VerificationReport,
    VerificationStatus,
    VerificationStepResult,
)
from aegify.scanner.engine import ScanEngine
from aegify.scanner.workspace import JvmClasspathArtifact, WorkspaceRepository
from aegify.semantic.jvm_bytecode import JvmBytecodeImporter, JvmClasspathSnapshot
from aegify.semantic.jvm_classpath import (
    JvmClasspathBundleMaterializer,
    JvmClasspathPlanner,
)
from aegify.semantic.jvm_classpath_exporter import (
    ClasspathRecord,
    JvmClasspathBundleBuilder,
    JvmClasspathExporter,
)

PINNED_IMAGE = f"example.invalid/aegify-jvm@sha256:{'c' * 64}"


def _jar(path: Path, content: bytes = b"library") -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.bin", content)
        archive.writestr(
            "META-INF/maven/com.acme/contracts/pom.properties",
            "groupId=com.acme\nartifactId=contracts\nversion=1.2.3\n",
        )
    return path


def test_bundle_is_deterministic_materializes_and_imports(tmp_path: Path):
    jar = _jar(tmp_path / "contracts.jar")
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    builder = JvmClasspathBundleBuilder()
    arguments = {
        "repository_id": "orders",
        "build_root_key": "root",
        "build_system": "gradle",
        "target_java": 17,
        "records": [
            ClasspathRecord("api", (jar,)),
            ClasspathRecord("batch", (jar,)),
        ],
    }

    snapshot = builder.build(first, **arguments)
    builder.build(second, **arguments)

    assert first.read_bytes() == second.read_bytes()
    assert len(snapshot.entries) == 2
    assert {entry.module for entry in snapshot.entries} == {"api", "batch"}
    assert snapshot.entries[0].coordinate is not None
    assert snapshot.entries[0].coordinate.artifact == "contracts"

    destination = tmp_path / "materialized"
    evidence = JvmClasspathBundleMaterializer().materialize(
        first,
        destination,
        expected_repository_id="orders",
    )

    assert evidence.entries == 2
    assert evidence.unique_jars == 1
    assert evidence.bundle_sha256 == hashlib.sha256(first.read_bytes()).hexdigest()
    assert evidence.snapshot_path == destination / "classpath.json"
    parsed = JvmClasspathSnapshot.model_validate_json(evidence.snapshot_path.read_bytes())
    assert parsed.repository_id == "orders"

    repository_root = tmp_path / "orders"
    repository_root.mkdir()
    imported = JvmBytecodeImporter().load(
        JvmClasspathArtifact(path=evidence.snapshot_path),
        WorkspaceRepository(id="orders", path=repository_root),
    )
    assert imported.summary.classpath_entries == 2
    assert imported.summary.entries_verified == 2
    assert imported.summary.entries_rejected == 0
    assert {
        relationship.source
        for relationship in imported.relationships
        if relationship.kind == "loads-jvm-artifact"
    } == {
        "repo:orders:jvm-module:root:api",
        "repo:orders:jvm-module:root:batch",
    }


def test_materializer_rejects_undeclared_or_unsafe_bundle_members(tmp_path: Path):
    bundle = tmp_path / "unsafe.zip"
    manifest = {
        "contract_version": 1,
        "repository_id": "app",
        "producer": {"name": "test", "version": ""},
        "target_java": 17,
        "entries": [],
    }
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("classpath.json", json.dumps(manifest))
        archive.writestr("../escape.jar", b"unsafe")

    with pytest.raises(ValueError, match="exactly match"):
        JvmClasspathBundleMaterializer().materialize(
            bundle,
            tmp_path / "output",
            expected_repository_id="app",
        )
    assert not (tmp_path / "escape.jar").exists()


def test_materializer_rejects_manifest_hash_mismatch(tmp_path: Path):
    bundle = tmp_path / "mismatch.zip"
    digest = "0" * 64
    manifest = {
        "contract_version": 1,
        "repository_id": "app",
        "producer": {"name": "test", "version": ""},
        "target_java": 17,
        "entries": [
            {
                "path": f"jars/{digest}.jar",
                "sha256": digest,
                "scope": "compile",
                "build_root": "root",
                "module": "root",
            }
        ],
    }
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("classpath.json", json.dumps(manifest))
        archive.writestr(f"jars/{digest}.jar", b"tampered")

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        JvmClasspathBundleMaterializer().materialize(
            bundle,
            tmp_path / "output",
            expected_repository_id="app",
        )
    assert not (tmp_path / "output").exists()


def test_maven_export_runs_offline_argv_and_builds_single_bundle(tmp_path: Path):
    root = tmp_path / "service"
    root.mkdir()
    (root / "pom.xml").write_text("<project/>\n")
    jar = _jar(tmp_path / "dependency.jar")
    commands: list[list[str]] = []

    def runner(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        output_argument = next(item for item in command if item.startswith("-Dmdep.outputFile="))
        relative = output_argument.split("=", 1)[1]
        output = cwd / relative
        output.parent.mkdir(parents=True)
        output.write_text(str(jar))
        return subprocess.CompletedProcess(command, 0)

    bundle = root / "aegify-classpath.zip"
    JvmClasspathExporter(runner).export(
        root,
        bundle,
        repository_id="service",
        build_root_key="root",
        build_system="maven",
        target_java=17,
    )

    assert commands[0][0] == "mvn"
    assert "-o" in commands[0]
    assert "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath" in commands[0]
    assert all(item not in {"sh", "bash", "-c"} for item in commands[0])
    with zipfile.ZipFile(bundle) as archive:
        snapshot = JvmClasspathSnapshot.model_validate_json(archive.read("classpath.json"))
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].module == "root"


def test_gradle_export_uses_offline_init_script_and_preserves_module(tmp_path: Path):
    root = tmp_path / "service"
    root.mkdir()
    (root / "settings.gradle.kts").write_text('include("api")\n')
    jar = _jar(tmp_path / "dependency.jar")
    commands: list[list[str]] = []

    def runner(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        script = Path(command[command.index("-I") + 1]).read_text()
        match = re.search(r"new File\('([^']+)'", script)
        assert match is not None
        record_root = Path(match.group(1))
        record_root.mkdir(parents=True)
        (record_root / "api.json").write_text(json.dumps({"module": "api", "files": [str(jar)]}))
        return subprocess.CompletedProcess(command, 0)

    bundle = root / "aegify-classpath.zip"
    JvmClasspathExporter(runner).export(
        root,
        bundle,
        repository_id="service",
        build_root_key="root",
        build_system="gradle",
        target_java=21,
    )

    assert commands[0][0] == "gradle"
    assert "--offline" in commands[0]
    assert "--no-daemon" in commands[0]
    with zipfile.ZipFile(bundle) as archive:
        snapshot = JvmClasspathSnapshot.model_validate_json(archive.read("classpath.json"))
    assert snapshot.target_java == 21
    assert snapshot.entries[0].module == "api"


def test_planner_emits_one_no_network_export_per_independent_build(tmp_path: Path):
    repository = tmp_path / "commerce"
    nested = repository / "tools"
    nested.mkdir(parents=True)
    (repository / "settings.gradle.kts").write_text('include("api", "domain")\n')
    (repository / "build.gradle.kts").write_text("plugins { java }\n")
    (nested / "pom.xml").write_text("<project/>\n")
    manifest = tmp_path / "workspace.yml"
    manifest.write_text("version: 1\nrepositories:\n  - id: commerce\n    path: ./commerce\n")

    planned = JvmClasspathPlanner().plan(
        manifest,
        PINNED_IMAGE,
        target_java=21,
    )

    repository_plan = planned.repositories[0]
    assert planned.target_java == 21
    assert {target.working_directory for target in repository_plan.targets} == {
        ".",
        "tools",
    }
    assert repository_plan.verification_plan.policy.network == "none"
    assert repository_plan.verification_plan.policy.tmpfs_executable is True
    docker_command = (
        DockerVerificationExecutor("docker")
        .plan(
            repository_plan.verification_plan,
            repository,
        )
        .docker_commands[0]
    )
    tmpfs = docker_command[docker_command.index("--tmpfs") + 1]
    assert tmpfs == "/tmp:rw,nosuid,nodev,exec,size=4g"
    assert "noexec" not in tmpfs
    for step in repository_plan.verification_plan.steps:
        assert step.command[:3] == [
            "python",
            "-m",
            "aegify.semantic.jvm_classpath_exporter",
        ]
        assert step.outputs == ["aegify-classpath.zip"]
        assert all(item not in {"sh", "bash", "-c"} for item in step.command)
    with pytest.raises(ValueError, match="pinned"):
        JvmClasspathPlanner().plan(manifest, "mutable:latest")
    with pytest.raises(ValueError, match="between 8 and 99"):
        JvmClasspathPlanner().plan(manifest, PINNED_IMAGE, target_java=100)


def test_classpath_cli_dry_run_emits_plan_and_execute_requires_approval(
    tmp_path: Path,
):
    repository = tmp_path / "service"
    repository.mkdir()
    (repository / "pom.xml").write_text("<project/>\n")
    (repository / "App.java").write_text("class App { void run() {} }\n")
    manifest = tmp_path / "workspace.yml"
    manifest.write_text("version: 1\nrepositories:\n  - id: service\n    path: ./service\n")
    runner = CliRunner()

    dry_run = runner.invoke(
        app,
        [
            "export-jvm-classpath",
            str(manifest),
            "--image",
            PINNED_IMAGE,
        ],
    )
    rejected = runner.invoke(
        app,
        [
            "export-jvm-classpath",
            str(manifest),
            "--image",
            PINNED_IMAGE,
            "--execute",
        ],
    )

    assert dry_run.exit_code == 0, dry_run.stdout
    payload = json.loads(dry_run.stdout)
    assert payload["executed"] is False
    assert payload["repositories"][0]["verification"]["status"] == "planned"
    assert rejected.exit_code == 2
    assert "requires --approve-build" in rejected.stdout


def test_classpath_cli_execute_materializes_retained_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    repository = tmp_path / "service"
    repository.mkdir()
    (repository / "pom.xml").write_text("<project/>\n")
    jar = _jar(tmp_path / "dependency.jar")
    manifest = tmp_path / "workspace.yml"
    manifest.write_text("version: 1\nrepositories:\n  - id: service\n    path: ./service\n")
    retained = tmp_path / "retained"

    class FakeExecutor:
        def execute(
            self,
            plan: object,
            workspace: Path,
            artifact_directory: Path,
        ) -> VerificationReport:
            del workspace
            verification_plan = plan
            step = verification_plan.steps[0]  # type: ignore[attr-defined]
            bundle = artifact_directory / step.id / step.outputs[0]
            JvmClasspathBundleBuilder().build(
                bundle,
                repository_id="service",
                build_root_key="root",
                build_system="maven",
                target_java=17,
                records=[ClasspathRecord("root", (jar,))],
            )
            artifact = VerificationArtifact(
                relative_path=step.outputs[0],
                retained_path=str(bundle),
                size_bytes=bundle.stat().st_size,
                sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(),
            )
            return VerificationReport(
                plan_name="jvm-classpath-service",
                status=VerificationStatus.PASSED,
                executed=True,
                image=PINNED_IMAGE,
                workspace_sha256=f"sha256:{'0' * 64}",
                policy_sha256=f"sha256:{'1' * 64}",
                steps=[
                    VerificationStepResult(
                        id=step.id,
                        status=VerificationStatus.PASSED,
                        command=step.command,
                        container_name="fake",
                        exit_code=0,
                        artifacts=[artifact],
                    )
                ],
            )

    monkeypatch.setattr(aegify.harness, "DockerVerificationExecutor", FakeExecutor)
    result = CliRunner().invoke(
        app,
        [
            "export-jvm-classpath",
            str(manifest),
            "--image",
            PINNED_IMAGE,
            "--execute",
            "--approve-build",
            "--artifact-directory",
            str(retained),
        ],
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    materialized = payload["repositories"][0]["materialized_snapshots"][0]
    snapshot = Path(materialized["snapshot_path"])
    assert snapshot.is_file()
    assert snapshot.is_relative_to(retained)
    assert materialized["entries"] == 1

    manifest.write_text(
        "version: 1\nrepositories:\n"
        "  - id: service\n"
        "    path: ./service\n"
        "    jvm_classpath_snapshots:\n"
        f"      - path: {snapshot}\n"
    )
    config = AegifyConfig()
    config.scan.max_workers = 1
    scan = ScanEngine(config=config).scan_workspace(manifest)
    assert scan.status == "completed"
    assert scan.semantic_analysis.jvm_classpath_snapshots == 1
    assert scan.semantic_analysis.jvm_classpath_entries_verified == 1
