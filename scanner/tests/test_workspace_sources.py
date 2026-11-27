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
    monkeypatch.delenv("AEGIFY_AZURE_REPOS_ENTRA_TOKEN", raising=False)
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
        host = sources._source({"url": url, "revision": commit}, sources.HOSTS)[2]
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
        "https://dev.azure.com/team/Invoice%20Tools/_git/Invoice%20API",
        "https://TEAM@Dev.Azure.com/team/Invoice%20Tools/_git/Invoice%20API",
        "https://team.visualstudio.com/Invoice%20Tools/_git/Invoice%20API",
        "https://team.visualstudio.com/DefaultCollection/Invoice%20Tools/_git/Invoice%20API",
    ],
)
def test_azure_clone_addresses_use_one_transport_and_receipt(
    url, tmp_path, history, local_transport, monkeypatch
):
    _, commit, tree = history
    bearer = "synthetic.enterprise.token"
    monkeypatch.setenv("AEGIFY_AZURE_REPOS_ENTRA_TOKEN", bearer)
    monkeypatch.setenv("AEGIFY_AZURE_REPOS_TOKEN", "unused-fixture-pat")
    monkeypatch.delenv("AEGIFY_GITHUB_TOKEN", raising=False)
    manifest = tmp_path / "sources.yml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "repositories": [
                    {"id": "azure", "source": {"url": url, "revision": commit}},
                    {"id": "github", "source": {"url": URLS[0], "revision": commit}},
                ]
            }
        )
    )
    output = tmp_path / "prepared"
    result = CliRunner().invoke(app, ["prepare-workspace", str(manifest), "-o", str(output)])
    assert result.exit_code == 0, result.output
    (azure_url, azure_env), (_, github_env) = local_transport
    expected = "https://dev.azure.com/team/Invoice%20Tools/_git/Invoice%20API"
    assert azure_url == expected
    assert azure_env["GIT_CONFIG_KEY_0"] == f"http.{expected}.extraHeader"
    assert azure_env["GIT_CONFIG_VALUE_0"] == f"Authorization: Bearer {bearer}"
    assert "GIT_CONFIG_VALUE_0" not in github_env
    assert "AEGIFY_AZURE_REPOS_ENTRA_TOKEN" not in azure_env
    receipt_data = (output / "sources.json").read_text()
    record = json.loads(receipt_data)["repositories"][0]
    assert (record["url"], record["commit"], record["tree"]) == (expected, commit, tree)
    assert bearer not in receipt_data + result.output + (output / "workspace.yml").read_text()


def test_invalid_azure_bearer_stops_before_fetch(tmp_path, history, local_transport, monkeypatch):
    _, commit, _ = history
    manifest = tmp_path / "sources.yml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "repositories": [
                    {"id": "one", "source": {"url": URLS[3], "revision": commit}},
                ]
            }
        )
    )
    monkeypatch.setenv("AEGIFY_AZURE_REPOS_ENTRA_TOKEN", "fixture-token\r\nsecond-header")
    output = tmp_path / "prepared"
    result = CliRunner().invoke(app, ["prepare-workspace", str(manifest), "-o", str(output)])
    assert result.exit_code == 2
    assert "fixture-token" not in result.output
    assert not local_transport and not output.exists()


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
        "https://other@dev.azure.com/team/p/_git/repo",
        "https://team:private-token@dev.azure.com/team/p/_git/repo",
        "https://private-token@team.visualstudio.com/p/_git/repo",
        "https://team.visualstudio.com.evil.test/p/_git/repo",
        "https://team.visualstudio.com:443/p/_git/repo",
        "https://foo.bar.visualstudio.com/p/_git/repo",
        "https://team@dev.azure.com:443/team/p/_git/repo",
        "https://team@dev.azure.com@evil.test/team/p/_git/repo",
        "https://team.visualstudio.com/DefaultCollection/../_git/repo",
        "https://team.visualstudio.com/%2e%2e/_git/repo",
        "https://team@dev.azure.com/team/p/_git/repo?access_token=private-token",
        "https://github.com.example.test/o/r",
        "https://github.com/o/r#ref",
        "https://github.com/o/r\n",
        "file:///tmp/repo",
    ],
)
def test_rejects_other_transports_and_secrets(url):
    with pytest.raises(ValueError) as caught:
        sources._source({"url": url, "revision": "b" * 40}, sources.HOSTS)
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


def test_scan_workspace_prepares_hosted_sources_and_uses_original_config(
    tmp_path, history, local_transport
):
    _, commit, _ = history
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "repositories": [
                    {"id": "remote", "source": {"url": URLS[0], "revision": commit}},
                ]
            }
        )
    )
    (tmp_path / ".aegify.yml").write_text("scan:\n  exclude: ['**/service.py', 'service.py']\n")
    report = tmp_path / "scan.json"
    output = tmp_path / "frozen"
    outcome = CliRunner().invoke(
        app,
        [
            "scan-workspace",
            str(manifest),
            "--prepare-to",
            str(output),
            "-o",
            "json",
            "-f",
            str(report),
        ],
    )
    assert outcome.exit_code in {0, 3}, outcome.output
    result = json.loads(report.read_text())
    assert all("service.py" not in file for file in result["analyzed_files"])
    assert json.loads((output / "sources.json").read_text())["repositories"][0]["commit"] == commit
    again = CliRunner().invoke(app, ["scan-workspace", str(manifest), "--prepare-to", str(output)])
    assert again.exit_code == 2


def test_self_managed_credentials_and_mixed_workspace(
    tmp_path, history, local_transport, monkeypatch
):
    _, commit, tree = history
    aliases = [
        {
            "host": "Code.example.test",
            "provider": "github",
            "token_env": "AEGIFY_WORKSPACE_TOKEN_CODE",
        },
        {
            "host": "git.example.test:8443",
            "provider": "gitlab",
            "token_env": "AEGIFY_WORKSPACE_TOKEN_TEAM",
        },
        {"host": "shared.example.test", "provider": "gitlab"},
    ]
    monkeypatch.setenv("AEGIFY_WORKSPACE_GIT_HOSTS", json.dumps(aliases))
    ca = tmp_path / "enterprise-ca.pem"
    ca.write_text("test CA path")
    monkeypatch.setenv("AEGIFY_WORKSPACE_GIT_CA_FILE", str(ca))
    monkeypatch.setenv("AEGIFY_WORKSPACE_TOKEN_CODE", "code-secret")
    monkeypatch.setenv("AEGIFY_WORKSPACE_TOKEN_TEAM", "team-secret")
    monkeypatch.setenv("AEGIFY_GITLAB_TOKEN", "cloud-secret")
    urls = [
        "https://code.example.test/team/app.git",
        "https://git.example.test:8443/org/subgroup/service.git",
        "https://shared.example.test/org/subgroup/third.git",
        URLS[1],
    ]
    manifest = tmp_path / "sources.yml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "repositories": [
                    {"id": f"app-{i}", "source": {"url": url, "revision": commit}}
                    for i, url in enumerate(urls)
                ]
            }
        )
    )
    out = tmp_path / "ready"
    result = CliRunner().invoke(app, ["scan-workspace", str(manifest), "--prepare-to", str(out)])
    assert result.exit_code in {0, 1, 3}, result.output
    receipts = (out / "sources.json").read_text()
    rows = json.loads(receipts)["repositories"]
    assert [row["provider"] for row in rows] == [
        "github-enterprise",
        "gitlab-self-managed",
        "gitlab-self-managed",
        "gitlab",
    ]
    assert all(row["commit"] == commit and row["tree"] == tree for row in rows)
    assert [row["url"] for row in rows] == urls
    for (url, env), credential in zip(
        local_transport,
        ["x-access-token:code-secret", "oauth2:team-secret", None, "oauth2:cloud-secret"],
        strict=True,
    ):
        assert env.get("GIT_SSL_CAINFO") == (None if url == URLS[1] else str(ca))
        if credential is None:
            assert "GIT_CONFIG_VALUE_0" not in env
        else:
            expected = base64.b64encode(credential.encode()).decode()
            assert env["GIT_CONFIG_KEY_0"] == f"http.{url}.extraHeader"
            assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {expected}"
            assert expected not in receipts + result.output
        assert not any(key.startswith("AEGIFY_") for key in env)


@pytest.mark.parametrize(
    "entry",
    [
        {"host": "example.test/path", "provider": "gitlab"},
        {"host": "*.example.test", "provider": "gitlab"},
        {"host": "user@example.test", "provider": "gitlab"},
        {"host": "example.test:65536", "provider": "gitlab"},
        {"host": "example.test:bad", "provider": "github"},
        {"host": "github.com:8443", "provider": "github"},
        {"host": "team.visualstudio.com", "provider": "gitlab"},
        {"host": "example.test", "provider": "gitlab", "token_env": "AEGIFY_GITLAB_TOKEN"},
        {"host": "example.test", "provider": "github", "token": "private-data"},
        {"host": "example.test", "provider": []},
    ],
)
def test_invalid_operator_policy_excludes_values(monkeypatch, entry):
    monkeypatch.setenv("AEGIFY_WORKSPACE_GIT_HOSTS", json.dumps([entry]))
    with pytest.raises(ValueError, match="^invalid AEGIFY_WORKSPACE_GIT_HOSTS configuration$"):
        sources._configured_hosts()


@pytest.mark.parametrize(
    "url",
    [
        "https://git.example.test/team/repo",
        "https://git.example.test:8444/team/repo",
        "https://git.example.test.evil.test:8443/team/repo",
        "https://team@git.example.test:8443/team/repo",
        "http://git.example.test:8443/team/repo",
        "https://git.example.test:8443/team/../repo",
        "https://code.example.test/group/subgroup/repo",
    ],
)
def test_custom_source_requires_exact_operator_authority(monkeypatch, url):
    monkeypatch.setenv(
        "AEGIFY_WORKSPACE_GIT_HOSTS",
        json.dumps(
            [
                {"host": "git.example.test:8443", "provider": "gitlab"},
                {"host": "code.example.test", "provider": "github"},
            ]
        ),
    )
    with pytest.raises(ValueError):
        sources._source({"url": url, "revision": "a" * 40}, sources._configured_hosts())


def test_host_policy_cannot_come_from_manifest(tmp_path, history, local_transport, monkeypatch):
    monkeypatch.delenv("AEGIFY_WORKSPACE_GIT_HOSTS", raising=False)
    _, commit, _ = history
    path = tmp_path / "workspace.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "git_hosts": [{"host": "private.example.test", "provider": "gitlab"}],
                "repositories": [
                    {
                        "id": "app",
                        "source": {
                            "url": "https://private.example.test/org/app",
                            "revision": commit,
                        },
                    }
                ],
            }
        )
    )
    output = tmp_path / "ready"
    result = CliRunner().invoke(app, ["prepare-workspace", str(path), "-o", str(output)])
    assert result.exit_code == 2
    assert not output.exists() and not local_transport


def test_invalid_enterprise_ca_prevents_fetch(tmp_path, history, local_transport, monkeypatch):
    monkeypatch.setenv(
        "AEGIFY_WORKSPACE_GIT_HOSTS", '[{"host":"private.example.test","provider":"gitlab"}]'
    )
    monkeypatch.setenv("AEGIFY_WORKSPACE_GIT_CA_FILE", "relative-cert.pem")
    _, commit, _ = history
    path = tmp_path / "workspace.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "repositories": [
                    {
                        "id": "app",
                        "source": {
                            "url": "https://private.example.test/org/app",
                            "revision": commit,
                        },
                    },
                ]
            }
        )
    )
    output = tmp_path / "ready"
    result = CliRunner().invoke(app, ["prepare-workspace", str(path), "-o", str(output)])
    assert result.exit_code == 2 and "absolute CA bundle" in " ".join(result.output.split())
    assert not output.exists() and not local_transport
