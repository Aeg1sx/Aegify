"""Tests for isolated scip-java planning across JVM repositories."""

from pathlib import Path

from codeguard.semantic.scip_java import ScipJavaPlanner

PINNED_IMAGE = f"ghcr.io/scip-code/scip-java@sha256:{'b' * 64}"


def test_planner_emits_one_index_step_per_independent_build_root(tmp_path: Path):
    gradle = tmp_path / "gradle-service"
    maven = tmp_path / "maven-service"
    nested = gradle / "tools"
    nested.mkdir(parents=True)
    maven.mkdir()
    (gradle / "settings.gradle.kts").write_text('include("app")\n')
    (gradle / "build.gradle.kts").write_text(
        'plugins { id("maven-publish") }\npublishing { publications {} }\n'
    )
    (nested / "pom.xml").write_text("<project/>\n")
    (maven / "pom.xml").write_text("<project/>\n")
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\n"
        "repositories:\n"
        "  - id: gradle\n"
        "    path: ./gradle-service\n"
        "  - id: maven\n"
        "    path: ./maven-service\n"
    )

    planned = ScipJavaPlanner().plan(manifest, PINNED_IMAGE)

    assert {repository.repository_id for repository in planned.repositories} == {
        "gradle",
        "maven",
    }
    gradle_plan = next(
        repository for repository in planned.repositories if repository.repository_id == "gradle"
    )
    assert {target.working_directory for target in gradle_plan.targets} == {".", "tools"}
    root_target = next(target for target in gradle_plan.targets if target.working_directory == ".")
    assert root_target.build_system == "gradle"
    assert root_target.cross_repository_metadata
    assert all(
        step.command == ["scip-java", "index"] and step.outputs == ["index.scip"]
        for step in gradle_plan.verification_plan.steps
    )
    assert gradle_plan.verification_plan.policy.network == "none"


def test_planner_requires_digest_pinned_image_and_warns_on_gradle_metadata(
    tmp_path: Path,
):
    repository = tmp_path / "service"
    repository.mkdir()
    (repository / "settings.gradle").write_text("rootProject.name = 'service'\n")
    (repository / "build.gradle").write_text("plugins { id 'java' }\n")
    manifest = tmp_path / "workspace.yml"
    manifest.write_text("version: 1\nrepositories:\n  - id: service\n    path: ./service\n")

    planned = ScipJavaPlanner().plan(manifest, PINNED_IMAGE)

    assert any(
        "maven-publish/publication metadata was not detected" in warning
        for warning in planned.repositories[0].warnings
    )
