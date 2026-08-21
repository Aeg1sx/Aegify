"""SCIP package-coordinate resolution and shard-cache regressions."""

import json
from pathlib import Path

from codeguard.scanner.ast_parser import ASTParser
from codeguard.scanner.workspace import WorkspaceManifest
from codeguard.semantic import SemanticAnalyzer
from codeguard.semantic.scip import ScipImporter
from codeguard.semantic.scip_symbol import parse_scip_symbol


def _index(path: Path, relative: str, symbol: str, *, definition: bool) -> None:
    path.write_text(
        json.dumps(
            {
                "metadata": {"toolInfo": {"name": "scip-java", "version": "test"}},
                "documents": [
                    {
                        "relativePath": relative,
                        "occurrences": [
                            {
                                "range": [0, 0, 1],
                                "symbol": symbol,
                                "symbolRoles": 1 if definition else 8,
                            }
                        ],
                        "symbols": [],
                    }
                ],
            }
        )
    )


def test_scip_symbol_parser_preserves_escaped_package_coordinate():
    parsed = parse_scip_symbol("scip-java maven com.example 1.2.3 com/example/Service#run().")
    escaped = parse_scip_symbol("scip  java maven com  example 1.0 Type#run().")

    assert parsed is not None and parsed.package is not None
    assert parsed.package.manager == "maven"
    assert parsed.package.name == "com.example"
    assert parsed.package.version == "1.2.3"
    assert parsed.descriptors == "com/example/Service#run()."
    assert escaped is not None and escaped.package is not None
    assert escaped.scheme == "scip java"
    assert escaped.package.name == "com example"
    assert parse_scip_symbol("local 17") is not None


def test_cross_repo_scip_resolution_is_exact_version_and_reports_conflict(
    tmp_path: Path,
):
    consumer = tmp_path / "consumer"
    provider_v1 = tmp_path / "provider-v1"
    provider_v2 = tmp_path / "provider-v2"
    for directory, class_name in (
        (consumer, "Consumer"),
        (provider_v1, "ProviderV1"),
        (provider_v2, "ProviderV2"),
    ):
        directory.mkdir()
        (directory / f"{class_name}.java").write_text(f"class {class_name} {{ void run() {{}} }}\n")
    symbol_v1 = "scip-java maven com.acme:shared 1.0 Service#run()."
    symbol_v2 = "scip-java maven com.acme:shared 2.0 Service#run()."
    _index(tmp_path / "consumer.json", "Consumer.java", symbol_v1, definition=False)
    _index(tmp_path / "provider-v1.json", "ProviderV1.java", symbol_v1, definition=True)
    _index(tmp_path / "provider-v2.json", "ProviderV2.java", symbol_v2, definition=True)
    manifest_path = tmp_path / "workspace.yml"
    manifest_path.write_text(
        "version: 1\n"
        "scip_cache_dir: ./.codeguard-cache/scip\n"
        "repositories:\n"
        "  - id: consumer\n"
        "    path: ./consumer\n"
        "    scip_index: ./consumer.json\n"
        "  - id: provider-v1\n"
        "    path: ./provider-v1\n"
        "    scip_index: ./provider-v1.json\n"
        "  - id: provider-v2\n"
        "    path: ./provider-v2\n"
        "    scip_index: ./provider-v2.json\n"
    )
    manifest = WorkspaceManifest.load(manifest_path)
    parser = ASTParser()
    asts = [
        parser.parse_file(
            repository.path / next(repository.path.glob("*.java")).name,
            repository_id=repository.id,
            repository_root=repository.path,
        )
        for repository in manifest.repositories
    ]

    bundle = SemanticAnalyzer().analyze(manifest, [ast for ast in asts if ast is not None])

    assert bundle.summary.scip_packages == 2
    assert bundle.summary.scip_exact_external_resolutions == 1
    assert bundle.summary.scip_unresolved_external_symbols == 0
    assert bundle.summary.scip_package_version_conflicts == 1
    assert bundle.summary.scip_cache_misses == 3
    conflicts = [edge for edge in bundle.relationships if edge.kind == "package-version-conflict"]
    assert len(conflicts) == 2
    assert all(edge.fidelity == "compiler-index" for edge in conflicts)

    cached = SemanticAnalyzer().analyze(manifest, [ast for ast in asts if ast is not None])
    assert cached.summary.scip_cache_hits == 3
    assert cached.summary.scip_cache_misses == 0
    assert cached.summary.scip_exact_external_resolutions == 1


def test_scip_content_cache_hits_and_invalidates_by_digest(tmp_path: Path):
    index = tmp_path / "index.json"
    cache = tmp_path / "cache"
    symbol = "scip-java maven com.acme:lib 1.0 Service#run()."
    _index(index, "Service.java", symbol, definition=True)
    importer = ScipImporter(cache_dir=cache)

    first = importer.load(index, "service")
    second = importer.load(index, "service")
    _index(
        index,
        "Service.java",
        "scip-java maven com.acme:lib 1.1 Service#run().",
        definition=True,
    )
    changed = importer.load(index, "service")

    assert first.cache_hit is False
    assert second.cache_hit is True
    assert changed.cache_hit is False
    assert first.content_sha256 != changed.content_sha256
    assert len(list(cache.glob("*.json"))) == 2
