"""Tests for parallel AST parsing and incremental build."""

from pathlib import Path

from aegify.config import AegifyConfig
from aegify.models import ScanStatus
from aegify.scanner.engine import ScanEngine
from aegify.storage import InMemoryBackend

FIXTURES = Path(__file__).parent / "fixtures"


class TestParallelParsing:
    def test_parallel_scan_produces_same_results(self):
        """Parallel and sequential scans should produce equivalent results."""
        config_seq = AegifyConfig()
        config_seq.llm.enabled = False
        config_seq.rules.severity_threshold = "low"
        config_seq.scan.max_workers = 1

        config_par = AegifyConfig()
        config_par.llm.enabled = False
        config_par.rules.severity_threshold = "low"
        config_par.scan.max_workers = 2

        engine_seq = ScanEngine(config=config_seq)
        engine_par = ScanEngine(config=config_par)

        result_seq = engine_seq.scan(FIXTURES)
        result_par = engine_par.scan(FIXTURES)

        assert result_seq.status == ScanStatus.COMPLETED
        assert result_par.status == ScanStatus.COMPLETED
        assert result_seq.files_scanned == result_par.files_scanned

    def test_single_file_no_parallelization(self):
        """Single file scan should work without parallelization."""
        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.scan.max_workers = 4

        engine = ScanEngine(config=config)
        result = engine.scan(FIXTURES / "vulnerable_app.py")

        assert result.status == ScanStatus.COMPLETED
        assert result.files_scanned == 1
        assert len(result.findings) > 0

    def test_max_workers_config(self):
        """max_workers=0 should auto-detect."""
        config = AegifyConfig()
        config.scan.max_workers = 0

        engine = ScanEngine(config=config)
        assert engine.max_workers >= 1
        assert engine.max_workers <= 8

    def test_explicit_workers(self):
        config = AegifyConfig()
        config.scan.max_workers = 3

        engine = ScanEngine(config=config)
        assert engine.max_workers == 3


class TestIncrementalBuild:
    def test_storage_backend_default(self):
        """Default storage backend should be InMemoryBackend."""
        config = AegifyConfig()
        config.llm.enabled = False

        engine = ScanEngine(config=config)
        assert isinstance(engine.storage, InMemoryBackend)

    def test_sqlite_storage_config(self):
        """SQLite storage backend should be created from config."""
        import tempfile

        from aegify.storage.sqlite import SQLiteBackend

        config = AegifyConfig()
        config.llm.enabled = False
        config.storage.backend = "sqlite"

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            config.storage.db_path = f.name

        engine = ScanEngine(config=config)
        assert isinstance(engine.storage, SQLiteBackend)
        engine.storage.close()
        Path(config.storage.db_path).unlink(missing_ok=True)

    def test_scan_with_storage(self):
        """Scan should work with storage backend."""
        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"

        storage = InMemoryBackend()
        engine = ScanEngine(config=config, storage=storage)

        result = engine.scan(FIXTURES / "vulnerable_app.py")
        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) > 0
