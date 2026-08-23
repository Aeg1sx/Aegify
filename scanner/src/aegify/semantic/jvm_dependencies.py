"""Maven/Gradle artifact coordinates and workspace provider resolution."""

from __future__ import annotations

import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from aegify.models import JvmBuildProject, SemanticRelationship
from aegify.scanner.workspace import WorkspaceRepository


@dataclass(frozen=True, order=True)
class JvmArtifactCoordinate:
    """An exact JVM distribution coordinate."""

    manager: str
    group: str
    artifact: str
    version: str

    @property
    def family(self) -> tuple[str, str, str]:
        return (self.manager, self.group, self.artifact)

    @property
    def node_id(self) -> str:
        encoded = [
            quote(value, safe="")
            for value in (self.manager, self.group, self.artifact, self.version)
        ]
        return f"jvm-artifact:{encoded[0]}:{encoded[1]}:{encoded[2]}@{encoded[3]}"


@dataclass(frozen=True)
class _DependencyFact:
    repository_id: str
    source_node: str
    coordinate: JvmArtifactCoordinate
    file_path: str
    fidelity: str


@dataclass
class JvmDependencyAnalysis:
    """Normalized external artifact facts and coverage counters."""

    artifacts: set[JvmArtifactCoordinate] = field(default_factory=set)
    relationships: list[SemanticRelationship] = field(default_factory=list)
    published_artifacts: int = 0
    declared_dependencies: int = 0
    locked_dependencies: int = 0
    dynamic_dependencies: int = 0
    lockfiles: int = 0
    version_catalogs: int = 0
    catalog_dependencies: int = 0
    exact_external_resolutions: int = 0
    ambiguous_external_resolutions: int = 0
    unresolved_workspace_dependencies: int = 0
    version_conflicts: int = 0
    warnings: list[str] = field(default_factory=list)


class JvmDependencyAnalyzer:
    """Resolve exact build coordinates without invoking Maven or Gradle.

    Descriptor declarations are evidence of intended classpath membership;
    Gradle dependency locks are stronger evidence of a selected version.  The
    resolver deliberately does not claim that an artifact was downloaded or
    loaded by a compiler unless a compiler index supplies that fact.
    """

    _PROPERTY = re.compile(r"\$\{([^}]+)}")
    _DYNAMIC_VERSION = re.compile(r"[+*\[\](),]|\$|\{")
    _GRADLE_VALUE = {
        "group": re.compile(r"(?m)^\s*group\s*=\s*['\"]([^'\"]+)['\"]"),
        "version": re.compile(r"(?m)^\s*version\s*=\s*['\"]([^'\"]+)['\"]"),
        "artifact": re.compile(
            r"(?m)^\s*(?:archivesName|archivesBaseName)\s*=\s*['\"]([^'\"]+)['\"]"
        ),
    }
    _GRADLE_ROOT_NAME = re.compile(r"(?m)^\s*rootProject\.name\s*=\s*['\"]([^'\"]+)['\"]")
    _GRADLE_DEPENDENCY = re.compile(
        r"\b(?P<scope>api|compileOnly|implementation|runtimeOnly|testImplementation|"
        r"testRuntimeOnly)\s*\(?\s*['\"]"
        r"(?P<group>[^:'\"]+):(?P<artifact>[^:'\"]+):(?P<version>[^'\"]+)['\"]"
    )
    _GRADLE_CATALOG_DEPENDENCY = re.compile(
        r"\b(?P<scope>api|compileOnly|implementation|runtimeOnly|testImplementation|"
        r"testRuntimeOnly)\s*\(\s*libs\.(?P<alias>[A-Za-z0-9_.-]+)\s*\)"
    )

    def analyze(
        self,
        repositories: list[WorkspaceRepository],
        projects: list[JvmBuildProject],
    ) -> JvmDependencyAnalysis:
        result = JvmDependencyAnalysis()
        repositories_by_id = {repository.id: repository for repository in repositories}
        published: dict[JvmArtifactCoordinate, set[tuple[str, str]]] = {}
        declared: set[tuple[str, JvmArtifactCoordinate]] = set()
        locked: set[tuple[str, JvmArtifactCoordinate]] = set()
        dynamic: set[tuple[str, str, str, str]] = set()
        effective: dict[tuple[str, JvmArtifactCoordinate], _DependencyFact] = {}
        seen_poms: set[Path] = set()
        seen_gradle_roots: set[Path] = set()

        for project in projects:
            repository = repositories_by_id.get(project.repository_id)
            if repository is None:
                continue
            if project.build_system == "maven":
                for descriptor in project.descriptors:
                    pom = Path(descriptor).resolve()
                    if pom.name != "pom.xml" or pom in seen_poms:
                        continue
                    seen_poms.add(pom)
                    publication, dependencies, unresolved = self._read_maven_pom(
                        pom,
                        repository,
                        result,
                    )
                    if publication is not None:
                        published.setdefault(publication, set()).add(
                            (
                                repository.id,
                                self._module_id(
                                    repository,
                                    pom.parent,
                                    "root",
                                ),
                            )
                        )
                    for fact in dependencies:
                        declared.add((repository.id, fact.coordinate))
                        effective[(repository.id, fact.coordinate)] = fact
                    dynamic.update(
                        (repository.id, group, artifact, version)
                        for group, artifact, version in unresolved
                    )
            elif project.build_system == "gradle":
                root = Path(project.root).resolve()
                if root in seen_gradle_roots:
                    continue
                seen_gradle_roots.add(root)
                publications, dependencies, unresolved = self._read_gradle_project(
                    root,
                    project,
                    repository,
                    result,
                )
                for publication, module_node in publications:
                    published.setdefault(publication, set()).add((repository.id, module_node))
                for fact in dependencies:
                    declared.add((repository.id, fact.coordinate))
                    effective.setdefault((repository.id, fact.coordinate), fact)
                dynamic.update(
                    (repository.id, group, artifact, version)
                    for group, artifact, version in unresolved
                )
                for lockfile in self._lockfiles(root):
                    relative = self._relative(lockfile, repository.path)
                    if relative not in project.dependency_lockfiles:
                        project.dependency_lockfiles.append(relative)
                    result.lockfiles += 1
                    for coordinate in self._read_gradle_lockfile(lockfile, result):
                        locked.add((repository.id, coordinate))
                        effective[(repository.id, coordinate)] = _DependencyFact(
                            repository_id=repository.id,
                            source_node=self._module_id(
                                repository,
                                root,
                                self._lockfile_module(root, lockfile, project.modules),
                            ),
                            coordinate=coordinate,
                            file_path=relative,
                            fidelity="dependency-lock-exact",
                        )

        result.published_artifacts = sum(len(values) for values in published.values())
        result.declared_dependencies = len(declared)
        result.locked_dependencies = len(locked)
        result.dynamic_dependencies = len(dynamic)
        result.artifacts = set(published) | {fact.coordinate for fact in effective.values()}

        seen_relationships: set[tuple[str, str, str, str]] = set()
        for coordinate, providers in sorted(published.items()):
            for repository_id, module_node in sorted(providers):
                self._append_relationship(
                    result,
                    seen_relationships,
                    source=module_node,
                    target=coordinate.node_id,
                    kind="publishes-jvm-artifact",
                    repository_id=repository_id,
                    fidelity="build-descriptor-coordinate",
                    confidence=0.9,
                )
                self._append_relationship(
                    result,
                    seen_relationships,
                    source=f"repository:{repository_id}",
                    target=coordinate.node_id,
                    kind="repository-publishes-jvm-artifact",
                    repository_id=repository_id,
                    fidelity="build-descriptor-coordinate",
                    confidence=0.9,
                )

        for fact in sorted(
            effective.values(),
            key=lambda item: (
                item.repository_id,
                item.coordinate,
                item.file_path,
            ),
        ):
            coordinate = fact.coordinate
            self._append_relationship(
                result,
                seen_relationships,
                source=fact.source_node,
                target=coordinate.node_id,
                kind="depends-on-jvm-artifact",
                repository_id=fact.repository_id,
                file_path=fact.file_path,
                fidelity=fact.fidelity,
                confidence=0.98 if fact.fidelity == "dependency-lock-exact" else 0.86,
            )
            self._append_relationship(
                result,
                seen_relationships,
                source=f"repository:{fact.repository_id}",
                target=coordinate.node_id,
                kind="repository-depends-on-jvm-artifact",
                repository_id=fact.repository_id,
                file_path=fact.file_path,
                fidelity=fact.fidelity,
                confidence=0.98 if fact.fidelity == "dependency-lock-exact" else 0.86,
            )
            providers = published.get(coordinate, set())
            external = {
                (repository_id, module_node)
                for repository_id, module_node in providers
                if repository_id != fact.repository_id
            }
            if len(external) == 1:
                provider, provider_module = next(iter(external))
                resolved_fidelity = self._resolved_fidelity(fact.fidelity)
                self._append_relationship(
                    result,
                    seen_relationships,
                    source=coordinate.node_id,
                    target=provider_module,
                    kind="resolved-jvm-provider",
                    repository_id=fact.repository_id,
                    file_path=fact.file_path,
                    fidelity=resolved_fidelity,
                    confidence=0.98 if fact.fidelity == "dependency-lock-exact" else 0.9,
                )
                self._append_relationship(
                    result,
                    seen_relationships,
                    source=coordinate.node_id,
                    target=f"repository:{provider}",
                    kind="resolved-jvm-provider-repository",
                    repository_id=fact.repository_id,
                    file_path=fact.file_path,
                    fidelity=resolved_fidelity,
                    confidence=0.98 if fact.fidelity == "dependency-lock-exact" else 0.9,
                )
                result.exact_external_resolutions += 1
            elif len(external) > 1:
                result.ambiguous_external_resolutions += 1
            elif not providers:
                result.unresolved_workspace_dependencies += 1

        families: dict[tuple[str, str, str], set[JvmArtifactCoordinate]] = {}
        for coordinate in result.artifacts:
            families.setdefault(coordinate.family, set()).add(coordinate)
        conflicts = [
            sorted(coordinates)
            for coordinates in families.values()
            if len({coordinate.version for coordinate in coordinates}) > 1
        ]
        result.version_conflicts = len(conflicts)
        for coordinates in conflicts:
            for source in coordinates:
                for target in coordinates:
                    if source == target:
                        continue
                    self._append_relationship(
                        result,
                        seen_relationships,
                        source=source.node_id,
                        target=target.node_id,
                        kind="jvm-version-conflict",
                        repository_id="",
                        fidelity="coordinate-version-conflict",
                        confidence=1.0,
                    )
        return result

    def _read_maven_pom(
        self,
        pom: Path,
        repository: WorkspaceRepository,
        result: JvmDependencyAnalysis,
    ) -> tuple[
        JvmArtifactCoordinate | None,
        list[_DependencyFact],
        set[tuple[str, str, str]],
    ]:
        try:
            root = ET.parse(pom).getroot()
        except (OSError, ET.ParseError) as error:
            result.warnings.append(f"{pom}: {error}")
            return None, [], set()
        parent = self._direct_child(root, "parent")
        group = self._direct_text(root, "groupId") or self._direct_text(parent, "groupId")
        artifact = self._direct_text(root, "artifactId")
        version = self._direct_text(root, "version") or self._direct_text(parent, "version")
        properties = self._maven_properties(root)
        properties.update(
            {
                "project.groupId": group,
                "pom.groupId": group,
                "project.artifactId": artifact,
                "pom.artifactId": artifact,
                "project.version": version,
                "pom.version": version,
            }
        )
        group = self._resolve(group, properties)
        artifact = self._resolve(artifact, properties)
        version = self._resolve(version, properties)
        publication = (
            JvmArtifactCoordinate("maven", group, artifact, version)
            if self._exact(group, artifact, version)
            else None
        )

        managed: dict[tuple[str, str], str] = {}
        management = self._direct_child(root, "dependencyManagement")
        managed_dependencies = self._direct_child(management, "dependencies")
        for dependency in self._children(managed_dependencies, "dependency"):
            dep_group = self._resolve(self._direct_text(dependency, "groupId"), properties)
            dep_artifact = self._resolve(self._direct_text(dependency, "artifactId"), properties)
            dep_version = self._resolve(self._direct_text(dependency, "version"), properties)
            if dep_group and dep_artifact and dep_version:
                managed[(dep_group, dep_artifact)] = dep_version

        facts: list[_DependencyFact] = []
        unresolved: set[tuple[str, str, str]] = set()
        dependencies = self._direct_child(root, "dependencies")
        for dependency in self._children(dependencies, "dependency"):
            scope = self._resolve(self._direct_text(dependency, "scope"), properties)
            if scope == "test":
                continue
            dep_group = self._resolve(self._direct_text(dependency, "groupId"), properties)
            dep_artifact = self._resolve(self._direct_text(dependency, "artifactId"), properties)
            dep_version = self._resolve(
                self._direct_text(dependency, "version"), properties
            ) or managed.get((dep_group, dep_artifact), "")
            if not self._exact(dep_group, dep_artifact, dep_version):
                unresolved.add((dep_group, dep_artifact, dep_version))
                continue
            facts.append(
                _DependencyFact(
                    repository_id=repository.id,
                    source_node=self._module_id(repository, pom.parent, "root"),
                    coordinate=JvmArtifactCoordinate("maven", dep_group, dep_artifact, dep_version),
                    file_path=self._relative(pom, repository.path),
                    fidelity="declared-coordinate",
                )
            )
        return publication, facts, unresolved

    def _read_gradle_project(
        self,
        root: Path,
        project: JvmBuildProject,
        repository: WorkspaceRepository,
        result: JvmDependencyAnalysis,
    ) -> tuple[
        set[tuple[JvmArtifactCoordinate, str]],
        list[_DependencyFact],
        set[tuple[str, str, str]],
    ]:
        settings = self._read_text(root / "settings.gradle.kts", root / "settings.gradle")
        root_name_match = self._GRADLE_ROOT_NAME.search(settings)
        root_name = root_name_match.group(1) if root_name_match else root.name
        root_build = self._read_text(root / "build.gradle.kts", root / "build.gradle")
        root_group = self._gradle_value(root_build, "group")
        root_version = self._gradle_value(root_build, "version")
        catalog_path = root / "gradle" / "libs.versions.toml"
        catalog: dict[str, list[JvmArtifactCoordinate]] = {}
        if catalog_path.is_file():
            result.version_catalogs += 1
            catalog = self._read_version_catalog(catalog_path, result)
        publications: set[tuple[JvmArtifactCoordinate, str]] = set()
        facts: list[_DependencyFact] = []
        unresolved: set[tuple[str, str, str]] = set()
        modules = ["root", *project.modules]
        for module in dict.fromkeys(modules):
            module_path = module.strip(":").replace(":", "/")
            module_root = root if module == "root" else root / module_path
            build_files = [
                module_root / "build.gradle.kts",
                module_root / "build.gradle",
            ]
            text = self._read_text(*build_files)
            group = self._gradle_value(text, "group") or root_group
            version = self._gradle_value(text, "version") or root_version
            artifact = self._gradle_value(text, "artifact") or (
                root_name if module == "root" else Path(module_path).name
            )
            if self._exact(group, artifact, version):
                publications.add(
                    (
                        JvmArtifactCoordinate("maven", group, artifact, version),
                        self._module_id(repository, root, module_path),
                    )
                )
            descriptor = next((path for path in build_files if path.is_file()), None)
            file_path = self._relative(descriptor, repository.path) if descriptor else ""
            for match in self._GRADLE_DEPENDENCY.finditer(text):
                if match.group("scope").startswith("test"):
                    continue
                dep_group = match.group("group")
                dep_artifact = match.group("artifact")
                dep_version = match.group("version")
                if not self._exact(dep_group, dep_artifact, dep_version):
                    unresolved.add((dep_group, dep_artifact, dep_version))
                    continue
                facts.append(
                    _DependencyFact(
                        repository_id=repository.id,
                        source_node=self._module_id(repository, root, module_path),
                        coordinate=JvmArtifactCoordinate(
                            "maven", dep_group, dep_artifact, dep_version
                        ),
                        file_path=file_path,
                        fidelity="declared-coordinate",
                    )
                )
            for match in self._GRADLE_CATALOG_DEPENDENCY.finditer(text):
                if match.group("scope").startswith("test"):
                    continue
                accessor = self._catalog_key(match.group("alias"))
                coordinates = catalog.get(accessor, [])
                if not coordinates:
                    unresolved.add(("catalog", accessor, ""))
                    continue
                result.catalog_dependencies += len(coordinates)
                for coordinate in coordinates:
                    facts.append(
                        _DependencyFact(
                            repository_id=repository.id,
                            source_node=self._module_id(repository, root, module_path),
                            coordinate=coordinate,
                            file_path=file_path,
                            fidelity="version-catalog-coordinate",
                        )
                    )
        return publications, facts, unresolved

    def _read_version_catalog(
        self,
        path: Path,
        result: JvmDependencyAnalysis,
    ) -> dict[str, list[JvmArtifactCoordinate]]:
        try:
            with path.open("rb") as stream:
                document = tomllib.load(stream)
        except (OSError, tomllib.TOMLDecodeError) as error:
            result.warnings.append(f"{path}: {error}")
            return {}
        versions = {
            str(key): self._catalog_version(value)
            for key, value in dict(document.get("versions", {})).items()
        }
        aliases: dict[str, list[JvmArtifactCoordinate]] = {}
        raw_libraries = dict(document.get("libraries", {}))
        for alias, raw in raw_libraries.items():
            coordinate = self._catalog_coordinate(raw, versions)
            if coordinate is not None:
                aliases[self._catalog_key(str(alias))] = [coordinate]
        for bundle, members in dict(document.get("bundles", {})).items():
            if not isinstance(members, list):
                continue
            coordinates = [
                coordinate
                for member in members
                for coordinate in aliases.get(self._catalog_key(str(member)), [])
            ]
            if coordinates:
                aliases[f"bundles.{self._catalog_key(str(bundle))}"] = coordinates
        return aliases

    def _catalog_coordinate(
        self,
        raw: object,
        versions: dict[str, str],
    ) -> JvmArtifactCoordinate | None:
        if isinstance(raw, str):
            parts = raw.split(":")
            return (
                JvmArtifactCoordinate("maven", *parts)
                if len(parts) == 3 and self._exact(*parts)
                else None
            )
        if not isinstance(raw, dict):
            return None
        module = raw.get("module")
        if isinstance(module, str) and ":" in module:
            group, artifact = module.split(":", 1)
        else:
            group = str(raw.get("group", ""))
            artifact = str(raw.get("name", ""))
        version_value = raw.get("version", "")
        version = self._catalog_version(version_value)
        if isinstance(version_value, dict):
            reference = str(version_value.get("ref", ""))
            if reference:
                version = versions.get(reference, "")
        dotted_reference = raw.get("version.ref")
        if dotted_reference:
            version = versions.get(str(dotted_reference), "")
        return (
            JvmArtifactCoordinate("maven", group, artifact, version)
            if self._exact(group, artifact, version)
            else None
        )

    @staticmethod
    def _catalog_version(raw: object) -> str:
        if isinstance(raw, str):
            return raw
        if isinstance(raw, dict):
            for key in ("require", "strictly", "prefer"):
                value = raw.get(key)
                if isinstance(value, str) and value:
                    return value
        return ""

    @staticmethod
    def _catalog_key(value: str) -> str:
        return re.sub(r"[-_.]+", ".", value).strip(".").lower()

    @staticmethod
    def _resolved_fidelity(dependency_fidelity: str) -> str:
        if dependency_fidelity == "dependency-lock-exact":
            return "dependency-lock-workspace-exact"
        if dependency_fidelity == "version-catalog-coordinate":
            return "version-catalog-workspace-exact"
        return "declared-coordinate-workspace-exact"

    def _read_gradle_lockfile(
        self,
        path: Path,
        result: JvmDependencyAnalysis,
    ) -> set[JvmArtifactCoordinate]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            result.warnings.append(f"{path}: {error}")
            return set()
        coordinates: set[JvmArtifactCoordinate] = set()
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            coordinate_text, _, configurations = line.partition("=")
            if configurations:
                scopes = {item.strip().lower() for item in configurations.split(",")}
                if scopes and all(scope.startswith("test") for scope in scopes):
                    continue
            parts = coordinate_text.split(":")
            if len(parts) != 3 or not self._exact(*parts):
                continue
            coordinates.add(JvmArtifactCoordinate("maven", *parts))
        return coordinates

    @staticmethod
    def _lockfiles(root: Path) -> list[Path]:
        candidates = set(root.rglob("gradle.lockfile"))
        dependency_locks = root / "gradle" / "dependency-locks"
        if dependency_locks.is_dir():
            candidates.update(dependency_locks.glob("*.lockfile"))
        return sorted(path for path in candidates if ".gradle" not in path.parts)

    @staticmethod
    def _lockfile_module(root: Path, lockfile: Path, modules: list[str]) -> str:
        try:
            relative_parent = lockfile.parent.resolve().relative_to(root.resolve())
        except ValueError:
            return "root"
        module_paths = {module.strip(":").replace(":", "/"): module for module in modules}
        candidates = [
            (path, module)
            for path, module in module_paths.items()
            if path and relative_parent.parts[: len(Path(path).parts)] == Path(path).parts
        ]
        if not candidates:
            return "root"
        _, module = max(candidates, key=lambda item: len(Path(item[0]).parts))
        return module

    @classmethod
    def _maven_properties(cls, root: ET.Element) -> dict[str, str]:
        properties: dict[str, str] = {}
        node = cls._direct_child(root, "properties")
        if node is None:
            return properties
        for child in node:
            key = child.tag.rsplit("}", 1)[-1]
            properties[key] = (child.text or "").strip()
        return properties

    @classmethod
    def _resolve(cls, value: str, properties: dict[str, str]) -> str:
        resolved = value.strip()
        for _ in range(8):
            updated = cls._PROPERTY.sub(
                lambda match: properties.get(match.group(1), match.group(0)),
                resolved,
            )
            if updated == resolved:
                break
            resolved = updated
        return resolved

    @classmethod
    def _exact(cls, *values: str) -> bool:
        return bool(all(value and not cls._DYNAMIC_VERSION.search(value) for value in values))

    @staticmethod
    def _direct_child(node: ET.Element | None, name: str) -> ET.Element | None:
        if node is None:
            return None
        return next(
            (child for child in node if child.tag.rsplit("}", 1)[-1] == name),
            None,
        )

    @classmethod
    def _direct_text(cls, node: ET.Element | None, name: str) -> str:
        child = cls._direct_child(node, name)
        return (child.text or "").strip() if child is not None else ""

    @staticmethod
    def _children(node: ET.Element | None, name: str) -> list[ET.Element]:
        if node is None:
            return []
        return [child for child in node if child.tag.rsplit("}", 1)[-1] == name]

    @classmethod
    def _gradle_value(cls, text: str, key: str) -> str:
        match = cls._GRADLE_VALUE[key].search(text)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _read_text(*paths: Path) -> str:
        snippets: list[str] = []
        for path in paths:
            if not path.is_file():
                continue
            try:
                snippets.append(path.read_text(encoding="utf-8"))
            except OSError, UnicodeError:
                continue
        return "\n".join(snippets)

    @staticmethod
    def _relative(path: Path, root: Path) -> str:
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return path.as_posix()

    @staticmethod
    def _module_id(
        repository: WorkspaceRepository,
        build_root: Path,
        module: str,
    ) -> str:
        try:
            root_key = build_root.resolve().relative_to(repository.path.resolve()).as_posix()
        except ValueError:
            root_key = build_root.name
        root_key = "root" if root_key in {"", "."} else root_key
        module_key = module.strip(":").replace(":", "/") or "root"
        return f"repo:{repository.id}:jvm-module:{root_key}:{module_key}"

    @staticmethod
    def _append_relationship(
        result: JvmDependencyAnalysis,
        seen: set[tuple[str, str, str, str]],
        *,
        source: str,
        target: str,
        kind: str,
        repository_id: str,
        fidelity: str,
        confidence: float,
        file_path: str = "",
    ) -> None:
        key = (source, target, kind, repository_id)
        if key in seen:
            return
        seen.add(key)
        result.relationships.append(
            SemanticRelationship(
                source=source,
                target=target,
                kind=kind,
                repository_id=repository_id,
                file_path=file_path,
                confidence=confidence,
                provider="aegify-jvm-dependency",
                fidelity=fidelity,
            )
        )
