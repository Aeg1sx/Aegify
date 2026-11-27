"""Prepare owned local Git history without contacting any external host."""

import base64
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from aegify.cli import app
from aegify.scanner import workspace_sources as sources
from aegify.scanner.workspace import WorkspaceManifest


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


@pytest.fixture()
def history(tmp_path):
    repo = tmp_path / "origin"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.email", "fixture@example.test")
    git(repo, "config", "user.name", "Fixture")
    text = repo / "service.py"
    text.write_text('def version(): return "one"\n')
    text.chmod(0o755)
    (repo / "alias.py").symlink_to("../outside")
    (repo / ".gitattributes").write_text("service.py export-ignore filter=test\n")
    git(repo, "add", ".")
    git(repo, "update-index", "--add", "--cacheinfo", "160000," + "1" * 40 + ",vendor")
    git(repo, "commit", "-qm", "first")
    commit = git(repo, "rev-parse", "HEAD")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    text.write_text('def version(): return "two"\n')
    git(repo, "commit", "-qam", "second")
    return repo, commit, tree


@pytest.fixture()
def local_transport(history, monkeypatch):
    repo, _, _ = history
    real_git = sources._git
    fetches = []

    def transport(cwd, args, env, **options):
        if args[0] == "fetch":
            assert env["GIT_ALLOW_PROTOCOL"] == "https"
            assert env["GIT_CONFIG_NOSYSTEM"] == "1"
            assert env["GIT_CONFIG_GLOBAL"] == os.devnull
            assert env["GIT_TERMINAL_PROMPT"] == "0"
            assert not {"GIT_TRACE", "HTTPS_PROXY", "GIT_SSL_NO_VERIFY"} & set(env)
            assert "--depth=1" in args and "--no-recurse-submodules" in args
            fetches.append((args[-2], dict(env)))
            # Only replace the transport destination. Real Git verifies the historical
            # commit and extracts its raw blobs through the production path.
            args = [*args[:-2], repo.as_uri(), args[-1]]
            env = {**env, "GIT_ALLOW_PROTOCOL": "file"}
        real_git(cwd, args, env, **options)

    monkeypatch.setattr(sources, "_git", transport)
    return fetches


URLS = [
    "https://github.com/fixture/billing.git",
    "https://gitlab.com/fixture/team/platform/orders.git",
    "https://bitbucket.org/fixture/inventory.git",
    "https://dev.azure.com/fixture/Invoice%20Tools/_git/Invoice%20API",
]


def test_cli_mixed_source_snapshot(tmp_path, history, local_transport, monkeypatch):
    _, commit, tree = history
    local = tmp_path / "gateway"
    local.mkdir()
    (local / "application.yml").write_text("spring: {}\n")
    (tmp_path / "evidence.json").write_text("[]")
    manifest = tmp_path / "input.yml"
    repos = [
        {
            "id": "gateway",
            "path": "gateway",
            "role": "gateway",
            "runtime_artifacts": [{"format": "http-evidence-json", "path": "evidence.json"}],
        }
    ]
    for index, url in enumerate(URLS):
        repos.append(
            {
                "id": f"app-{index}",
                "depends_on": ["gateway"],
                "source": {"url": url, "revision": commit},
            }
        )
    for _, token_name, _ in sources.HOSTS.values():
        monkeypatch.setenv(token_name, token_name + "-secret")
    monkeypatch.setenv("GIT_TRACE", "1")
    manifest.write_text(yaml.safe_dump({"version": 1, "name": "ledger", "repositories": repos}))
    output = tmp_path / "ready"
    result = CliRunner().invoke(app, ["prepare-workspace", str(manifest), "-o", str(output)])
    assert result.exit_code == 0, result.output
    loaded = WorkspaceManifest.load(output / "workspace.yml")
    assert loaded.repositories[0].path == local
    assert loaded.repositories[0].runtime_artifacts[0].path == tmp_path / "evidence.json"
    receipts = json.loads((output / "sources.json").read_text())["repositories"]
    assert receipts[0] == {"id": "gateway", "provider": "local", "path": str(local)}
    for index, (url, env) in enumerate(local_transport):
        host = sources._source({"url": url, "revision": commit})[2]
        provider, token_name, username = sources.HOSTS[host]
        secret = token_name + "-secret"
        basic = base64.b64encode(f"{username}:{secret}".encode()).decode()
        assert env["GIT_CONFIG_KEY_0"] == f"http.{url}.extraHeader"
        assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {basic}"
        assert not any(key in env for _, key, _ in sources.HOSTS.values())
        receipt = receipts[index + 1]
        assert (receipt["provider"], receipt["tree"], receipt["commit"]) == (provider, tree, commit)
        assert receipt["files"] == 2 and receipt["skipped"] == {"symlinks": 1, "submodules": 1}
        prepared = loaded.repositories[index + 1].path
        assert (prepared / "service.py").read_text() == 'def version(): return "one"\n'
        assert not (prepared / "service.py").stat().st_mode & 0o111
        assert not (prepared / "alias.py").is_symlink()
        assert not (prepared / "vendor").exists() and not (prepared / ".git").exists()
        assert secret not in result.output + (output / "sources.json").read_text()
    assert len(local_transport) == 4
    scan = CliRunner().invoke(app, ["scan-workspace", str(output / "workspace.yml")])
    assert scan.exit_code in {0, 1, 3}, scan.output


@pytest.mark.parametrize(
    "url",
    [
        "git@github.com:owner/repo",
        "http://github.com/owner/repo",
        "https://user:private-token@github.com/owner/repo",
        "https://github.com/owner/repo?private-token",
        "https://gitlab.com/owner/../repo",
        "https://gitlab.com/group/%2e%2e/repo",
        "https://bitbucket.org:8443/team/repo",
        "https://dev.azure.com/o/p/repo",
        "https://github.com.example.test/o/r",
        "https://github.com/o/r#ref",
        "https://github.com/o/r\n",
        "file:///tmp/repo",
    ],
)
def test_rejects_other_transports_and_secrets(url):
    with pytest.raises(ValueError) as caught:
        sources._source({"url": url, "revision": "b" * 40})
    assert "private-token" not in str(caught.value)


def test_pin_and_output_are_fail_closed(tmp_path, history, local_transport, monkeypatch):
    _, commit, _ = history
    doc = tmp_path / "sources.yml"
    out = tmp_path / "prepared"

    def prepare(revision, *, first=False):
        urls = [(URLS[0], commit), (URLS[1], revision)] if first else [(URLS[0], revision)]
        doc.write_text(
            yaml.safe_dump(
                {
                    "repositories": [
                        {"id": f"service-{i}", "source": {"url": url, "revision": sha}}
                        for i, (url, sha) in enumerate(urls)
                    ]
                }
            )
        )
        return CliRunner().invoke(app, ["prepare-workspace", str(doc), "--output", str(out)])

    assert prepare("main").exit_code == 2
    assert not local_transport and not out.exists()
    assert prepare("c" * 40, first=True).exit_code == 2
    assert len(local_transport) == 2 and not out.exists()
    assert not list(tmp_path.glob(".aegify-prepare-*"))
    monkeypatch.setattr(sources, "FILE_BYTES", 4)
    assert prepare(commit).exit_code == 2 and not out.exists()
    out.mkdir()
    (out / "preserve").write_text("existing")
    assert prepare(commit).exit_code == 2
    assert (out / "preserve").read_text() == "existing"
