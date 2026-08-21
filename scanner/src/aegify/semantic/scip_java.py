"""Plan reproducible scip-java indexing for multi-repository JVM workspaces."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from aegify.harness.models import (
    VerificationPlan,
    VerificationPolicy,
    VerificationStep,
)
from aegify.scanner.workspace import WorkspaceManifest, WorkspaceRepository
from aegify.semantic.jvm import JvmBuildDiscoverer


class ScipJavaBuildTarget(BaseModel):
    """One independent Gradle or Maven build root."""

    step_id: str
    build_system: str
    working_directory: str
    expected_output: str = "index.scip"
    cross_repository_metadata: bool = False


class ScipJavaRepositoryPlan(BaseModel):
    """An isolated scip-java plan whose workspace is one repository."""

    repository_id: str
    workspace: Path
    targets: list[ScipJavaBuildTarget] = Field(default_factory=list)
    verification_plan: VerificationPlan
    warnings: list[str] = Field(default_factory=list)


class ScipJavaWorkspacePlan(BaseModel):
    """All JVM repository indexing plans for a Aegify workspace."""

    manifest: Path
    repositories: list[ScipJavaRepositoryPlan] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ScipJavaPlanner:
    """Discover build roots and emit argv-only, digest-pinned index plans."""

    def __init__(self) -> None:
        self.discoverer = JvmBuildDiscoverer()

    def plan(self, manifest_path: Path, image: str) -> ScipJavaWorkspacePlan:
        manifest = WorkspaceManifest.load(manifest_path)
        result = ScipJavaWorkspacePlan(manifest=manifest_path.resolve())
        for repository in manifest.repositories:
            planned = self._plan_repository(repository, image)
            if planned is not None:
                result.repositories.append(planned)
        if not result.repositories:
            result.warnings.append("workspace contains no discoverable Gradle or Maven builds")
        return result

    def _plan_repository(
        self,
        repository: WorkspaceRepository,
        image: str,
    ) -> ScipJavaRepositoryPlan | None:
        projects = self.discoverer.discover(repository)
        if not projects:
            return None
        by_root: dict[Path, set[str]] = {}
        for project in projects:
            by_root.setdefault(Path(project.root).resolve(), set()).add(project.build_system)

        targets: list[ScipJavaBuildTarget] = []
        steps: list[VerificationStep] = []
        warnings: list[str] = []
        for index, (root, systems) in enumerate(sorted(by_root.items()), start=1):
            build_system = self._choose_build_system(root, systems)
            relative = root.relative_to(repository.path.resolve())
            working_directory = relative.as_posix() if relative.parts else "."
            step_id = f"scip-{index}-{build_system}"
            cross_repo = self._cross_repository_metadata(root, build_system)
            targets.append(
                ScipJavaBuildTarget(
                    step_id=step_id,
                    build_system=build_system,
                    working_directory=working_directory,
                    cross_repository_metadata=cross_repo,
                )
            )
            steps.append(
                VerificationStep(
                    id=step_id,
                    command=["scip-java", "index"],
                    working_directory=working_directory,
                    timeout_seconds=1800,
                    outputs=["index.scip"],
                )
            )
            if len(systems) > 1:
                warnings.append(
                    f"{working_directory}: both Maven and Gradle descriptors exist; "
                    f"selected {build_system}"
                )
            if build_system == "gradle" and not cross_repo:
                warnings.append(
                    f"{working_directory}: Gradle maven-publish/publication metadata "
                    "was not detected; local navigation can work but cross-repository "
                    "symbols may remain unresolved"
                )
            if build_system == "maven" and self._contains_kotlin(root):
                warnings.append(
                    f"{working_directory}: scip-java automatic Maven indexing does not "
                    "support kotlin-maven-plugin; use Gradle or manual compiler-plugin setup"
                )

        plan = VerificationPlan(
            name=f"scip-java-{repository.id}",
            image=image,
            policy=VerificationPolicy(
                network="none",
                cpus=4.0,
                memory="4g",
                pids_limit=1024,
                tmpfs_size="1g",
                max_output_bytes=2_000_000,
                max_artifact_bytes=1_000_000_000,
            ),
            steps=steps,
        )
        warnings.append(
            "network is disabled during indexing; the digest-pinned image must contain "
            "scip-java plus all build dependencies and caches required by this repository"
        )
        return ScipJavaRepositoryPlan(
            repository_id=repository.id,
            workspace=repository.path,
            targets=targets,
            verification_plan=plan,
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

    @staticmethod
    def _cross_repository_metadata(root: Path, build_system: str) -> bool:
        if build_system == "maven":
            return (root / "pom.xml").is_file()
        snippets: list[str] = []
        for name in ("build.gradle", "build.gradle.kts"):
            path = root / name
            if path.is_file():
                try:
                    snippets.append(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError):
                    continue
        text = "\n".join(snippets)
        return "maven-publish" in text and "publishing" in text

    @staticmethod
    def _contains_kotlin(root: Path) -> bool:
        return any(root.rglob("src/*/kotlin/*.kt")) or any(root.rglob("src/*/kotlin/**/*.kt"))
