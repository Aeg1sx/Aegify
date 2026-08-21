"""Approved-build JVM classpath exporter used inside the isolated harness.

The exporter runs Maven or Gradle without a shell, captures resolved compile
classpath JARs, and emits one deterministic ZIP. The host-side materializer
validates that bundle again before a workspace scan can import it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from codeguard.semantic.jvm_bytecode import (
    JvmClasspathCoordinate,
    JvmClasspathProducer,
    JvmClasspathSnapshot,
    JvmClasspathSnapshotEntry,
)

CommandRunner = Callable[[list[str], Path], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class ClasspathRecord:
    """Resolved JARs for one module beneath an independent build root."""

    module: str
    jars: tuple[Path, ...]


class JvmClasspathBundleBuilder:
    """Build a deterministic, content-addressed classpath bundle."""

    def __init__(
        self,
        *,
        max_entries: int = 2_000,
        max_jar_bytes: int = 500_000_000,
        max_total_bytes: int = 2_000_000_000,
    ) -> None:
        self.max_entries = max_entries
        self.max_jar_bytes = max_jar_bytes
        self.max_total_bytes = max_total_bytes

    def build(
        self,
        output: Path,
        *,
        repository_id: str,
        build_root_key: str,
        build_system: str,
        target_java: int,
        records: Sequence[ClasspathRecord],
    ) -> JvmClasspathSnapshot:
        build_root = self._safe_key(build_root_key)
        retained: dict[str, Path] = {}
        entries: list[JvmClasspathSnapshotEntry] = []
        seen: set[tuple[str, str]] = set()
        total_bytes = 0
        for record in sorted(records, key=lambda item: item.module):
            module = self._safe_key(record.module)
            for jar in sorted({path.resolve() for path in record.jars}):
                if jar.is_symlink() or not jar.is_file() or jar.suffix.lower() != ".jar":
                    continue
                size = jar.stat().st_size
                if size > self.max_jar_bytes:
                    raise ValueError(f"classpath JAR exceeds {self.max_jar_bytes} bytes: {jar}")
                digest = self._sha256(jar)
                identity = (module, digest)
                if identity in seen:
                    continue
                seen.add(identity)
                if len(entries) >= self.max_entries:
                    raise ValueError(f"classpath exceeds {self.max_entries} entries")
                if digest not in retained:
                    total_bytes += size
                    if total_bytes > self.max_total_bytes:
                        raise ValueError(f"classpath exceeds {self.max_total_bytes} retained bytes")
                    retained[digest] = jar
                coordinate = self._infer_maven_coordinate(jar)
                entries.append(
                    JvmClasspathSnapshotEntry(
                        path=f"jars/{digest}.jar",
                        sha256=digest,
                        scope="compile",
                        build_root=build_root,
                        module=module,
                        coordinate=coordinate,
                    )
                )

        snapshot = JvmClasspathSnapshot(
            repository_id=repository_id,
            producer=JvmClasspathProducer(name=build_system),
            target_java=target_java,
            entries=sorted(
                entries,
                key=lambda item: (item.build_root, item.module, item.path),
            ),
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "w", allowZip64=True) as archive:
            manifest = (
                json.dumps(
                    snapshot.model_dump(mode="json"),
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8")
                + b"\n"
            )
            self._write_bytes(archive, "classpath.json", manifest)
            for digest, jar in sorted(retained.items()):
                self._write_file(archive, f"jars/{digest}.jar", jar)
        return snapshot

    @staticmethod
    def _safe_key(value: str) -> str:
        normalized = "root" if value in {"", ".", "root"} else value
        path = PurePosixPath(normalized.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"classpath module/build root escaped: {value}")
        return path.as_posix()

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1_048_576), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _zip_info(name: str) -> zipfile.ZipInfo:
        info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.external_attr = 0o100644 << 16
        return info

    @classmethod
    def _write_bytes(cls, archive: zipfile.ZipFile, name: str, content: bytes) -> None:
        archive.writestr(cls._zip_info(name), content)

    @classmethod
    def _write_file(cls, archive: zipfile.ZipFile, name: str, source: Path) -> None:
        with (
            source.open("rb") as input_stream,
            archive.open(
                cls._zip_info(name),
                "w",
                force_zip64=True,
            ) as output_stream,
        ):
            shutil.copyfileobj(input_stream, output_stream, length=1_048_576)

    @staticmethod
    def _infer_maven_coordinate(jar: Path) -> JvmClasspathCoordinate | None:
        try:
            with zipfile.ZipFile(jar) as archive:
                candidates = sorted(
                    (
                        info
                        for info in archive.infolist()
                        if info.filename.startswith("META-INF/maven/")
                        and info.filename.endswith("/pom.properties")
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
                    if "=" not in line or line.lstrip().startswith("#"):
                        continue
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip()
                group = values.get("groupId", "")
                artifact = values.get("artifactId", "")
                version = values.get("version", "")
                if all((group, artifact, version)):
                    return JvmClasspathCoordinate(
                        group=group,
                        artifact=artifact,
                        version=version,
                    )
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return None
        return None


class JvmClasspathExporter:
    """Resolve one Maven/Gradle build and emit its bounded classpath bundle."""

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner or self._default_runner

    def export(
        self,
        build_root: Path,
        output: Path,
        *,
        repository_id: str,
        build_root_key: str,
        build_system: str,
        target_java: int,
    ) -> JvmClasspathSnapshot:
        root = build_root.resolve()
        if not root.is_dir():
            raise ValueError(f"build root is not a directory: {root}")
        token = uuid.uuid4().hex
        if build_system == "maven":
            records = self._maven_records(root, token)
        elif build_system == "gradle":
            records = self._gradle_records(root, token)
        else:
            raise ValueError(f"unsupported JVM build system: {build_system}")
        return JvmClasspathBundleBuilder().build(
            output,
            repository_id=repository_id,
            build_root_key=build_root_key,
            build_system=build_system,
            target_java=target_java,
            records=records,
        )

    def _maven_records(self, root: Path, token: str) -> list[ClasspathRecord]:
        relative_output = f".codeguard-classpath/{token}.txt"
        repository_cache = self._runtime_cache("m2")
        wrapper = root / "mvnw"
        executable = (
            "./mvnw"
            if wrapper.is_file() and not wrapper.is_symlink() and os.access(wrapper, os.X_OK)
            else "mvn"
        )
        command = [
            executable,
            "-o",
            "-q",
            f"-Dmaven.repo.local={repository_cache}",
            "dependency:build-classpath",
            "-DincludeScope=compile",
            f"-Dmdep.outputFile={relative_output}",
        ]
        self._require_success(command, root)
        records: list[ClasspathRecord] = []
        for output in sorted(root.rglob(f".codeguard-classpath/{token}.txt")):
            module_root = output.parent.parent
            module = self._relative_module(root, module_root)
            paths = self._classpath_text(output)
            records.append(ClasspathRecord(module, tuple(paths)))
        return records

    def _gradle_records(self, root: Path, token: str) -> list[ClasspathRecord]:
        task_name = f"codeguardExportClasspath{token}"
        record_root = root / ".codeguard-classpath" / token
        user_home = self._runtime_cache("gradle")
        script = self._gradle_init_script(task_name, record_root)
        with tempfile.TemporaryDirectory(prefix="codeguard-classpath-") as directory:
            init_script = Path(directory) / "init.gradle"
            init_script.write_text(script, encoding="utf-8")
            wrapper = root / "gradlew"
            executable = (
                "./gradlew"
                if wrapper.is_file() and not wrapper.is_symlink() and os.access(wrapper, os.X_OK)
                else "gradle"
            )
            command = [
                executable,
                "--offline",
                "--no-daemon",
                "--console=plain",
                "--gradle-user-home",
                str(user_home),
                "-I",
                str(init_script),
                task_name,
            ]
            self._require_success(command, root)
        records: list[ClasspathRecord] = []
        for output in sorted(record_root.glob("*.json")):
            payload = json.loads(output.read_text(encoding="utf-8"))
            module = self._safe_record_module(payload.get("module"))
            raw_files = payload.get("files")
            if not isinstance(raw_files, list) or not all(
                isinstance(item, str) for item in raw_files
            ):
                raise ValueError(f"invalid Gradle classpath record: {output}")
            records.append(
                ClasspathRecord(
                    module,
                    tuple(Path(item) for item in raw_files),
                )
            )
        return records

    def _require_success(self, command: list[str], root: Path) -> None:
        completed = self.runner(command, root)
        if completed.returncode != 0:
            raise RuntimeError(f"{command[0]} classpath export exited with {completed.returncode}")

    @staticmethod
    def _default_runner(
        command: list[str],
        root: Path,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["HOME"] = tempfile.gettempdir()
        environment["XDG_CACHE_HOME"] = str(Path(tempfile.gettempdir()) / ".cache")
        return subprocess.run(
            command,
            cwd=root,
            check=False,
            env=environment,
            text=True,
            timeout=1_700,
        )

    @staticmethod
    def _runtime_cache(name: str) -> Path:
        destination = Path(tempfile.gettempdir()) / f"codeguard-{name}"
        source = Path("/opt/codeguard-cache") / name
        if destination.exists():
            return destination
        if source.is_dir():
            shutil.copytree(source, destination, symlinks=True)
        else:
            destination.mkdir(parents=True)
        return destination

    @staticmethod
    def _relative_module(root: Path, module_root: Path) -> str:
        relative = module_root.resolve().relative_to(root.resolve())
        return relative.as_posix() if relative.parts else "root"

    @staticmethod
    def _classpath_text(path: Path) -> list[Path]:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return []
        return [Path(value) for value in text.split(os.pathsep) if value]

    @staticmethod
    def _safe_record_module(value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("Gradle classpath record requires a module string")
        return JvmClasspathBundleBuilder._safe_key(value)

    @staticmethod
    def _gradle_init_script(task_name: str, record_root: Path) -> str:
        escaped_root = str(record_root).replace("\\", "\\\\").replace("'", "\\'")
        return (
            f"""
allprojects {{ project ->
    tasks.register('{task_name}') {{
        outputs.upToDateWhen {{ false }}
        doLast {{
            def configuration = configurations.findByName('compileClasspath')
            if (configuration == null) return
            def moduleKey = 'root'
            if (project.path != ':') {{
                moduleKey = project.path.substring(1).replace(':', '/')
            }}
            def digest = java.security.MessageDigest.getInstance('SHA-256')
                .digest(project.path.getBytes('UTF-8')).encodeHex().toString()
            def output = new File('{escaped_root}', digest + '.json')
            output.parentFile.mkdirs()
            def files = configuration.resolve()
                .findAll {{ it.isFile() && it.name.toLowerCase().endsWith('.jar') }}
                .collect {{ it.canonicalPath }}.sort()
            output.text = groovy.json.JsonOutput.toJson([module: moduleKey, files: files])
        }}
    }}
}}
""".strip()
            + "\n"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export a verified JVM classpath bundle")
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--build-system", required=True, choices=("maven", "gradle"))
    parser.add_argument("--build-root-key", default="root")
    parser.add_argument("--target-java", type=int, default=17, choices=range(8, 100))
    parser.add_argument("--output", default="codeguard-classpath.zip")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    output = PurePosixPath(arguments.output.replace("\\", "/"))
    if output.is_absolute() or ".." in output.parts:
        print("classpath output must stay beneath the build root", file=sys.stderr)
        return 2
    try:
        JvmClasspathExporter().export(
            Path.cwd(),
            Path.cwd() / output,
            repository_id=arguments.repository_id,
            build_root_key=arguments.build_root_key,
            build_system=arguments.build_system,
            target_java=arguments.target_java,
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"JVM classpath export failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
