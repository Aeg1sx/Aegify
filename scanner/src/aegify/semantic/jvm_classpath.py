"""Isolated JVM classpath planning and safe bundle materialization."""

from __future__ import annotations

import hashlib
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, Field

from aegify.harness.models import (
    VerificationPlan,
    VerificationPolicy,
    VerificationStep,
)
from aegify.scanner.workspace import (
    JvmClasspathArtifact,
    WorkspaceManifest,
    WorkspaceRepository,
)
from aegify.semantic.jvm import JvmBuildDiscoverer
from aegify.semantic.jvm_bytecode import JvmClasspathSnapshot


class JvmClasspathBuildTarget(BaseModel):
    """One independent build root and its retained bundle output."""

    step_id: str
    build_system: str
    working_directory: str
    build_root_key: str
    expected_output: str = "aegify-classpath.zip"


class JvmClasspathRepositoryPlan(BaseModel):
    """An isolated classpath plan whose workspace is one repository."""

    repository_id: str
    workspace: Path
    targets: list[JvmClasspathBuildTarget] = Field(default_factory=list)
    verification_plan: VerificationPlan
    warnings: list[str] = Field(default_factory=list)


class JvmClasspathWorkspacePlan(BaseModel):
    """Classpath export plans for all JVM repositories in a workspace."""

    manifest: Path
    target_java: int
    repositories: list[JvmClasspathRepositoryPlan] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class JvmClasspathMaterializedSnapshot(BaseModel):
    """Host-validated evidence produced from one isolated ZIP artifact."""

    bundle_path: Path
    bundle_sha256: str
    snapshot_path: Path
    snapshot_sha256: str
    repository_id: str
    entries: int
    unique_jars: int
    total_jar_bytes: int


class JvmClasspathPlanner:
    """Emit digest-pinned, no-network plans for Maven/Gradle classpaths."""

    def __init__(self) -> None:
        self.discoverer = JvmBuildDiscoverer()

    def plan(
        self,
        manifest_path: Path,
        image: str,
        *,
        target_java: int = 17,
    ) -> JvmClasspathWorkspacePlan:
        if not 8 <= target_java <= 99:
            raise ValueError("target Java must be between 8 and 99")
        manifest = WorkspaceManifest.load(manifest_path)
        result = JvmClasspathWorkspacePlan(
            manifest=manifest_path.resolve(),
            target_java=target_java,
        )
        for repository in manifest.repositories:
            planned = self._plan_repository(repository, image, target_java)
            if planned is not None:
                result.repositories.append(planned)
        if not result.repositories:
            result.warnings.append("workspace contains no discoverable Gradle or Maven builds")
        return result

    def _plan_repository(
        self,
        repository: WorkspaceRepository,
        image: str,
        target_java: int,
    ) -> JvmClasspathRepositoryPlan | None:
        projects = self.discoverer.discover(repository)
        if not projects:
            return None
        by_root: dict[Path, set[str]] = {}
        for project in projects:
            by_root.setdefault(Path(project.root).resolve(), set()).add(project.build_system)

        targets: list[JvmClasspathBuildTarget] = []
        steps: list[VerificationStep] = []
        warnings: list[str] = []
        for index, (root, systems) in enumerate(sorted(by_root.items()), start=1):
            build_system = self._choose_build_system(root, systems)
            relative = root.relative_to(repository.path.resolve())
            working_directory = relative.as_posix() if relative.parts else "."
            build_root_key = relative.as_posix() if relative.parts else "root"
            step_id = f"classpath-{index}-{build_system}"
            output = "aegify-classpath.zip"
            targets.append(
                JvmClasspathBuildTarget(
                    step_id=step_id,
                    build_system=build_system,
                    working_directory=working_directory,
                    build_root_key=build_root_key,
                    expected_output=output,
                )
            )
            steps.append(
                VerificationStep(
                    id=step_id,
                    command=[
                        "python",
                        "-m",
                        "aegify.semantic.jvm_classpath_exporter",
                        "--repository-id",
                        repository.id,
                        "--build-system",
                        build_system,
                        "--build-root-key",
                        build_root_key,
                        "--target-java",
                        str(target_java),
                        "--output",
                        output,
                    ],
                    working_directory=working_directory,
                    timeout_seconds=1_800,
                    outputs=[output],
                )
            )
            if len(systems) > 1:
                warnings.append(
                    f"{working_directory}: both Maven and Gradle descriptors exist; "
                    f"selected {build_system}"
                )

        verification_plan = VerificationPlan(
            name=f"jvm-classpath-{repository.id}",
            image=image,
            policy=VerificationPolicy(
                network="none",
                cpus=4.0,
                memory="6g",
                pids_limit=1_024,
                tmpfs_size="4g",
                tmpfs_executable=True,
                max_output_bytes=2_000_000,
                max_artifact_bytes=2_000_000_000,
            ),
            steps=steps,
        )
        warnings.append(
            "network is disabled; the pinned image must contain Python/Aegify, "
            "a JDK, Maven/Gradle, wrapper distributions, plugins, dependencies, and "
            "all caches required by this repository"
        )
        return JvmClasspathRepositoryPlan(
            repository_id=repository.id,
            workspace=repository.path,
            targets=targets,
            verification_plan=verification_plan,
            warnings=warnings,
        )

    @staticmethod
    def _choose_build_system(root: Path, systems: set[str]) -> str:
        if "gradle" in systems and (
            (root / "gradlew").is_file()
            or (root / "settings.gradle").is_file()
            or (root / "settings.gradle.kts").is_file()
        ):
            return "gradle"
        if "maven" in systems:
            return "maven"
        return sorted(systems)[0]


class JvmClasspathBundleMaterializer:
    """Validate and extract one classpath bundle without trusting ZIP paths."""

    _MAX_MANIFEST_BYTES = 10_000_000

    def materialize(
        self,
        bundle: Path,
        destination: Path,
        *,
        expected_repository_id: str | None = None,
        policy: JvmClasspathArtifact | None = None,
    ) -> JvmClasspathMaterializedSnapshot:
        limits = policy or JvmClasspathArtifact(path=bundle)
        source = bundle.resolve()
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"classpath bundle is not a regular file: {source}")
        if source.stat().st_size > limits.max_total_bytes + self._MAX_MANIFEST_BYTES:
            raise ValueError("classpath bundle exceeds the configured total size")
        target = destination.resolve()
        if target.exists():
            raise ValueError(f"classpath materialization destination exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=".aegify-classpath-", dir=target.parent))
        try:
            result = self._materialize_archive(
                source,
                temporary,
                expected_repository_id,
                limits,
            )
            temporary.rename(target)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return result.model_copy(update={"snapshot_path": target / "classpath.json"})

    def _materialize_archive(
        self,
        bundle: Path,
        destination: Path,
        expected_repository_id: str | None,
        limits: JvmClasspathArtifact,
    ) -> JvmClasspathMaterializedSnapshot:
        try:
            with zipfile.ZipFile(bundle) as archive:
                infos = archive.infolist()
                if len(infos) > limits.max_entries + 1:
                    raise ValueError("classpath bundle contains too many members")
                names = [info.filename for info in infos]
                if len(names) != len(set(names)):
                    raise ValueError("classpath bundle contains duplicate members")
                info_by_name = {info.filename: info for info in infos}
                manifest_info = info_by_name.get("classpath.json")
                if manifest_info is None:
                    raise ValueError("classpath bundle is missing classpath.json")
                self._validate_member(manifest_info, self._MAX_MANIFEST_BYTES, limits)
                manifest_bytes = archive.read(manifest_info)
                snapshot = JvmClasspathSnapshot.model_validate_json(manifest_bytes)
                if (
                    expected_repository_id is not None
                    and snapshot.repository_id != expected_repository_id
                ):
                    raise ValueError(
                        f"snapshot repository {snapshot.repository_id!r} does not "
                        f"match {expected_repository_id!r}"
                    )
                if len(snapshot.entries) > limits.max_entries:
                    raise ValueError("classpath snapshot contains too many entries")
                jar_names = {entry.path for entry in snapshot.entries}
                expected_names = {"classpath.json", *jar_names}
                if set(names) != expected_names:
                    raise ValueError("classpath bundle members do not exactly match the manifest")
                (destination / "classpath.json").write_bytes(manifest_bytes)
                total = 0
                for name in sorted(jar_names):
                    info = info_by_name[name]
                    self._validate_jar_name(name)
                    self._validate_member(info, limits.max_jar_bytes, limits)
                    total += info.file_size
                    if total > limits.max_total_bytes:
                        raise ValueError("classpath bundle exceeds retained byte limit")
                    expected_hashes = {
                        entry.sha256 for entry in snapshot.entries if entry.path == name
                    }
                    if len(expected_hashes) != 1:
                        raise ValueError(f"conflicting hashes for classpath member: {name}")
                    expected_hash = next(iter(expected_hashes))
                    output = destination / name
                    output.parent.mkdir(parents=True, exist_ok=True)
                    actual_hash = self._copy_member(archive, info, output)
                    if actual_hash != expected_hash:
                        raise ValueError(f"SHA-256 mismatch for classpath member: {name}")
        except zipfile.BadZipFile as error:
            raise ValueError(f"invalid classpath bundle: {error}") from error
        return JvmClasspathMaterializedSnapshot(
            bundle_path=bundle,
            bundle_sha256=self._sha256(bundle),
            snapshot_path=destination / "classpath.json",
            snapshot_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            repository_id=snapshot.repository_id,
            entries=len(snapshot.entries),
            unique_jars=len(jar_names),
            total_jar_bytes=total,
        )

    @staticmethod
    def _validate_jar_name(name: str) -> None:
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or len(path.parts) != 2
            or path.parts[0] != "jars"
            or re.fullmatch(r"[0-9a-f]{64}\.jar", path.parts[1]) is None
        ):
            raise ValueError(f"unsafe classpath bundle member: {name}")

    @staticmethod
    def _validate_member(
        info: zipfile.ZipInfo,
        max_bytes: int,
        limits: JvmClasspathArtifact,
    ) -> None:
        mode = info.external_attr >> 16
        if info.is_dir() or (mode and stat.S_ISLNK(mode)):
            raise ValueError(f"unsupported classpath bundle member: {info.filename}")
        if info.file_size > max_bytes:
            raise ValueError(f"classpath bundle member is too large: {info.filename}")
        ratio = info.file_size / max(info.compress_size, 1)
        if ratio > limits.max_compression_ratio:
            raise ValueError(
                f"classpath bundle member compression ratio is too high: {info.filename}"
            )

    @staticmethod
    def _copy_member(
        archive: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        output: Path,
    ) -> str:
        digest = hashlib.sha256()
        with archive.open(info) as source, output.open("wb") as destination:
            for chunk in iter(lambda: source.read(1_048_576), b""):
                digest.update(chunk)
                destination.write(chunk)
        return digest.hexdigest()

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1_048_576), b""):
                digest.update(chunk)
        return digest.hexdigest()
