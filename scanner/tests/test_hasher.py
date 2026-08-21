"""Tests for file hashing utilities."""

from codeguard.storage.hasher import compute_file_hash, compute_hashes


class TestFileHasher:
    def test_compute_file_hash_deterministic(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("print('hello')")

        h1 = compute_file_hash(f)
        h2 = compute_file_hash(f)
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex digest

    def test_different_content_different_hash(self, tmp_path):
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("content_a")
        f2.write_text("content_b")

        assert compute_file_hash(f1) != compute_file_hash(f2)

    def test_same_content_same_hash(self, tmp_path):
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("same_content")
        f2.write_text("same_content")

        assert compute_file_hash(f1) == compute_file_hash(f2)

    def test_compute_hashes_parallel(self, tmp_path):
        files = []
        for i in range(5):
            f = tmp_path / f"file_{i}.py"
            f.write_text(f"content_{i}")
            files.append(f)

        hashes = compute_hashes(files)
        assert len(hashes) == 5
        assert all(len(h) == 64 for h in hashes.values())
        # All different content = all different hashes
        assert len(set(hashes.values())) == 5

    def test_compute_hashes_small_batch_sequential(self, tmp_path):
        """Small batches (<=3) use sequential mode."""
        files = []
        for i in range(2):
            f = tmp_path / f"file_{i}.py"
            f.write_text(f"content_{i}")
            files.append(f)

        hashes = compute_hashes(files)
        assert len(hashes) == 2

    def test_empty_file_hash(self, tmp_path):
        f = tmp_path / "empty.py"
        f.write_text("")

        h = compute_file_hash(f)
        assert len(h) == 64  # Still a valid hash
