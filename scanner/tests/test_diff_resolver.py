import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from aegify.scanner.diff_resolver import DiffResolver


@pytest.mark.parametrize("value", ["--name-only", "base\nname", "base\x00name"])
def test_invalid_ci_base_is_rejected_before_git_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("GITHUB_BASE_SHA", "HEAD")
    with patch("aegify.scanner.diff_resolver.subprocess.run") as run:
        assert DiffResolver(tmp_path).get_changed_files(base_ref=value) == []
    run.assert_not_called()


def test_ci_base_follows_the_end_of_options_marker(tmp_path: Path) -> None:
    with patch("aegify.scanner.diff_resolver.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, stdout="")
        assert DiffResolver(tmp_path).get_changed_files(base_ref="refs/heads/integration") == []
    argv = run.call_args.args[0]
    assert argv[:2] == ["git", "diff"]
    assert argv[-4:] == ["--end-of-options", "refs/heads/integration", "HEAD", "--"]
    assert {"--name-only", "--no-ext-diff", "--no-textconv"} <= set(argv[2:-4])


def test_ci_base_uses_revision_even_if_its_name_is_also_a_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def git(*args: str) -> None:
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                *args,
            ],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )

    git("init", "-q")
    git("commit", "--allow-empty", "-qm", "base")
    git("tag", "baseline")
    (tmp_path / "baseline").touch()
    source = tmp_path / "view.py"
    source.write_text("title = 'Home'\n")
    git("add", "view.py")
    git("commit", "-qm", "add source")
    monkeypatch.setenv("GITHUB_BASE_SHA", "baseline")
    assert DiffResolver(tmp_path).get_changed_files() == [source]
