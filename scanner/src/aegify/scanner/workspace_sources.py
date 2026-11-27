"""Prepare local and commit-pinned hosted Git sources for a workspace scan."""

from __future__ import annotations

import base64
import json
import os
import re
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlsplit

import yaml

from aegify.scanner.gateway_inventory import canonical_host
from aegify.scanner.workspace import WorkspaceManifest, WorkspaceRepository

# One shallow pack, one bounded index, and one bounded batch of raw blobs per repository.
PACK_BYTES = 128 * 1024 * 1024
TREE_BYTES = 8 * 1024 * 1024
FILE_BYTES = 16 * 1024 * 1024
TOTAL_BYTES = 256 * 1024 * 1024
MAX_FILES = 25_000
type _Host = tuple[str, str, str]  # provider, token environment name, HTTPS username

HOSTS: dict[str, _Host] = {
    "github.com": ("github", "AEGIFY_GITHUB_TOKEN", "x-access-token"),
    "gitlab.com": ("gitlab", "AEGIFY_GITLAB_TOKEN", "oauth2"),
    "bitbucket.org": ("bitbucket", "AEGIFY_BITBUCKET_TOKEN", "x-bitbucket-api-token-auth"),
    "dev.azure.com": ("azure", "AEGIFY_AZURE_REPOS_TOKEN", ""),
}


def _configured_hosts() -> dict[str, _Host]:
    """Read transport policy from the operator environment, outside the source manifest."""
    raw = os.environ.get("AEGIFY_WORKSPACE_GIT_HOSTS")
    if raw is None:
        return HOSTS
    error = "invalid AEGIFY_WORKSPACE_GIT_HOSTS configuration"
    if len(raw) > 16_384:
        raise ValueError(error)
    try:
        entries = json.loads(raw)
    except ValueError, RecursionError:
        raise ValueError(error) from None
    if not isinstance(entries, list) or len(entries) > 32:
        raise ValueError(error)
    hosts = dict(HOSTS)
    providers = {
        "github": ("github-enterprise", "x-access-token"),
        "gitlab": ("gitlab-self-managed", "oauth2"),
    }
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) not in (
            {"host", "provider"},
            {"host", "provider", "token_env"},
        ):
            raise ValueError(error)
        authority = entry["host"]
        if not isinstance(authority, str):
            raise ValueError(error)
        hostname, colon, port = authority.lower().partition(":")
        if (
            canonical_host(hostname) != hostname
            or hostname in HOSTS
            or hostname.endswith(".visualstudio.com")
            or (colon and (not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535))
        ):
            raise ValueError(error)
        provider, token_env = entry["provider"], entry.get("token_env", "")
        if (
            authority.lower() in hosts
            or not isinstance(provider, str)
            or provider not in providers
            or not isinstance(token_env, str)
            or (
                "token_env" in entry
                and not re.fullmatch(r"AEGIFY_WORKSPACE_TOKEN_[A-Z0-9_]{1,64}", token_env)
            )
        ):
            raise ValueError(error)
        label, username = providers[provider]
        hosts[authority.lower()] = (label, token_env, username)
    return hosts


def _source(value: Any, hosts: dict[str, _Host]) -> tuple[str, str, str]:
    if not isinstance(value, dict) or set(value) != {"url", "revision"}:
        raise ValueError("source requires only url and revision")
    url, revision = value["url"], value["revision"]
    if not isinstance(revision, str) or not re.fullmatch("[a-fA-F0-9]{40}", revision):
        raise ValueError("revision must be a full 40-character commit SHA")
    if not isinstance(url, str) or not re.fullmatch(r"[!-~]{1,2048}", url):
        raise ValueError("source requires a canonical hosted Git HTTPS URL")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or "?" in url or "#" in url:
        raise ValueError("expected a hosted Git HTTPS URL without credentials or options")
    parts = parsed.path.removeprefix("/").removesuffix("/").split("/")
    host = parsed.netloc.lower()
    # Azure includes the organization as userinfo in its advertised Git URL.
    # Strip only that specific hint and send Git to the canonical provider host.
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*@dev\.azure\.com", host):
        organization, _, host = host.partition("@")
        if organization != parts[0].lower():
            raise ValueError("Azure clone URL organization does not match its path")
    legacy = re.fullmatch(r"([a-z0-9][a-z0-9-]*)\.visualstudio\.com", host)
    if legacy:
        if parts[0].lower() == "defaultcollection" and len(parts) == 4:
            parts = parts[1:]
        parts.insert(0, legacy[1])
        host = "dev.azure.com"
    if host not in hosts:
        raise ValueError("expected a hosted Git HTTPS URL without credentials or options")
    if host == "dev.azure.com":
        valid = len(parts) in {3, 4} and parts[-2] == "_git"
    elif hosts[host][0] in {"gitlab", "gitlab-self-managed"}:
        valid = 2 <= len(parts) <= 24
    else:
        valid = len(parts) == 2
    for part in parts:
        slug = part.replace("%20", " ") if host == "dev.azure.com" else part
        if (
            not re.fullmatch(r"[A-Za-z0-9._ -]+", slug)
            or slug in {".", "..", ".git"}
            or slug.strip() != slug
        ):
            valid = False
    if not valid:
        raise ValueError("invalid repository path for the selected HTTPS host")
    return f"https://{host}/{'/'.join(parts)}", revision.lower(), host


def _git(
    cwd: Path,
    args: list[str],
    env: dict[str, str],
    *,
    limit: int = PACK_BYTES,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
) -> None:
    # Limit both downloaded packfiles and file-backed command output. Git's HTTPS
    # transport and index-pack are children of the same bounded process group.
    if os.name != "posix":
        raise ValueError("preparing remote Git sources requires a POSIX Git environment")
    import resource

    def cap_output() -> None:
        _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        bound = limit if hard == resource.RLIM_INFINITY else min(hard, limit)
        resource.setrlimit(resource.RLIMIT_FSIZE, (bound, bound))

    process = subprocess.Popen(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "http.followRedirects=false",
            "-c",
            "fetch.fsckObjects=true",
            "-c",
            "fetch.unpackLimit=1",
            "-c",
            "gc.auto=0",
            *args,
        ],
        cwd=cwd,
        env=env,
        stdin=stdin or subprocess.DEVNULL,
        stdout=stdout or subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        preexec_fn=cap_output,
    )
    try:
        status = process.wait(timeout=120)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    if status:
        raise ValueError("Git operation failed. Check the commit, read access and size limits.")


def _materialize(
    url: str,
    revision: str,
    host_config: _Host,
    destination: Path,
    scratch: Path,
    remaining: int,
) -> dict[str, Any]:
    env = {
        "PATH": os.defpath,
        "HOME": str(scratch),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }
    bare = scratch / "objects.git"
    _git(scratch, ["init", "--bare", "--template=", str(bare)], env)
    provider, token_name, username = host_config
    transport = dict(env)
    if provider in {"github-enterprise", "gitlab-self-managed"}:
        ca_bundle = os.environ.get("AEGIFY_WORKSPACE_GIT_CA_FILE")
        if ca_bundle is not None:
            if not Path(ca_bundle).is_absolute() or not Path(ca_bundle).is_file():
                raise ValueError("AEGIFY_WORKSPACE_GIT_CA_FILE requires an absolute CA bundle path")
            transport["GIT_SSL_CAINFO"] = ca_bundle
    token = os.environ.get(token_name) if token_name else None
    bearer = os.environ.get("AEGIFY_AZURE_REPOS_ENTRA_TOKEN") if provider == "azure" else None
    if bearer:
        if not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", bearer):
            raise ValueError("invalid Azure Repos bearer token")
        authorization = f"Bearer {bearer}"
    elif token:
        credential = base64.b64encode(f"{username}:{token}".encode()).decode("ascii")
        authorization = f"Basic {credential}"
    else:
        authorization = ""
    if authorization:
        transport.update(
            GIT_CONFIG_COUNT="1",
            GIT_CONFIG_KEY_0=f"http.{url}.extraHeader",
            GIT_CONFIG_VALUE_0=f"Authorization: {authorization}",
        )
    _git(
        bare,
        [
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-recurse-submodules",
            "--depth=1",
            "--",
            url,
            revision,
        ],
        transport,
    )
    with tempfile.TemporaryFile() as info:
        _git(bare, ["rev-parse", "--verify", "FETCH_HEAD^{commit}"], env, stdout=info)
        info.seek(0)
        if info.read(128).strip() != revision.encode():
            raise ValueError("fetched object does not match the requested commit")
        info.seek(0)
        info.truncate()
        _git(bare, ["rev-parse", "--verify", revision + "^{tree}"], env, stdout=info)
        info.seek(0)
        tree = info.read(128).strip().decode("ascii")
    entries = []
    skips = {"symlinks": 0, "submodules": 0}
    total = 0
    with tempfile.TemporaryFile() as listing:
        _git(bare, ["ls-tree", "-rlz", revision], env, limit=TREE_BYTES, stdout=listing)
        listing.seek(0)
        lines = listing.read(TREE_BYTES + 1).split(b"\0")
    if len(lines) > MAX_FILES + 1:
        raise ValueError("repository has too many entries")
    for entry in lines:
        if not entry:
            continue
        meta, name = entry.split(b"\t", 1)
        mode, kind, oid, raw_size = meta.split()
        if mode == b"120000":
            skips["symlinks"] += 1
            continue
        if mode == b"160000":
            skips["submodules"] += 1
            continue
        segments = os.fsdecode(name).split("/")
        if any(
            not part
            or part in {".", ".."}
            or part.lower() == ".git"
            or "\\" in part
            or any(ord(char) < 32 for char in part)
            for part in segments
        ):
            raise ValueError("unsupported path in the Git tree")
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            raise ValueError("unsupported Git object in source tree")
        length = int(raw_size)
        total += length
        if length > FILE_BYTES or total > remaining:
            raise ValueError("source exceeds the workspace or per-file size limit")
        entries.append((destination.joinpath(*segments), oid, length))

    destination.mkdir()
    with tempfile.TemporaryFile() as batch, tempfile.TemporaryFile() as contents:
        for _, oid, _ in entries:
            batch.write(oid + b"\n")
        batch.seek(0)
        _git(
            bare,
            ["cat-file", "--batch"],
            env,
            stdin=batch,
            stdout=contents,
            limit=max(4096, total + 128 * len(entries)),
        )
        contents.seek(0)
        for path, oid, size in entries:
            if contents.readline(128).split() != [oid, b"blob", str(size).encode()]:
                raise ValueError("unexpected blob header")
            body = contents.read(size)
            if len(body) != size or contents.read(1) != b"\n":
                raise ValueError("incomplete Git blob")
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as file:
                file.write(body)
    return {
        "provider": provider,
        "url": url,
        "commit": revision,
        "tree": tree,
        "files": len(entries),
        "bytes": total,
        "skipped": skips,
    }


def _absolute(path: Any, base: Path) -> str:
    if not isinstance(path, str) or not path:
        raise ValueError("workspace paths must be nonempty strings")
    return str((base / path).resolve())


def prepare_workspace(manifest: Path, output: Path) -> Path:
    """Publish a scan-workspace manifest and receipts together after every source succeeds."""
    manifest = manifest.resolve()
    output = output.absolute()
    if os.path.lexists(output):
        raise ValueError("output directory already exists")
    with manifest.open("rb") as stream:
        data = stream.read(1_048_577)
    if len(data) > 1_048_576:
        raise ValueError("workspace manifest exceeds 1 MiB")
    try:
        spec = yaml.safe_load(data)
    except yaml.YAMLError:
        raise ValueError("invalid workspace YAML") from None
    if (
        not isinstance(spec, dict)
        or spec.get("version", 1) != 1
        or not isinstance(spec.get("repositories"), list)
        or not 1 <= len(spec["repositories"]) <= 32
    ):
        raise ValueError("expected a version 1 manifest with 1 to 32 repositories")
    if spec.get("scip_cache_dir") is not None:
        spec["scip_cache_dir"] = _absolute(spec["scip_cache_dir"], manifest.parent)
    seen: set[str] = set()
    remote: dict[str, tuple[str, str, str]] = {}
    hosts = (
        _configured_hosts()
        if any(isinstance(repo, dict) and "source" in repo for repo in spec["repositories"])
        else HOSTS
    )
    for repo in spec["repositories"]:
        if not isinstance(repo, dict) or ("path" in repo) == ("source" in repo):
            raise ValueError("each repository requires exactly one of path or source")
        if "source" in repo:
            url = _source(repo.pop("source"), hosts)
            repo["path"] = "."
        else:
            url = None
        try:
            validated = WorkspaceRepository.model_validate(repo)
        except ValueError:
            raise ValueError("invalid workspace repository fields") from None
        if validated.id.casefold() in seen:
            raise ValueError("duplicate repository id")
        seen.add(validated.id.casefold())
        if url:
            remote[validated.id] = url
            repo["path"] = str(Path("repos") / validated.id)
        else:
            repo["path"] = _absolute(repo["path"], manifest.parent)
        if repo.get("scip_index") is not None:
            repo["scip_index"] = _absolute(repo["scip_index"], manifest.parent)
        if "scip_indexes" in repo:
            repo["scip_indexes"] = [
                _absolute(item, manifest.parent) for item in repo["scip_indexes"]
            ]
        for field in ("analysis_artifacts", "runtime_artifacts", "jvm_classpath_snapshots"):
            for artifact in repo.get(field, []):
                artifact["path"] = _absolute(artifact["path"], manifest.parent)

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".aegify-prepare-", dir=output.parent) as tmp:
        stage = Path(tmp) / "workspace"
        stage.mkdir(mode=0o700)
        if remote:
            (stage / "repos").mkdir()
        receipts = []
        remaining = TOTAL_BYTES
        for repo in spec["repositories"]:
            rid = repo["id"]
            if rid in remote:
                with tempfile.TemporaryDirectory(dir=tmp) as scratch:
                    fetch_url, revision, host = remote[rid]
                    receipt = _materialize(
                        fetch_url,
                        revision,
                        hosts[host],
                        stage / repo["path"],
                        Path(scratch),
                        remaining,
                    )
                remaining -= receipt["bytes"]
            else:
                receipt = {"provider": "local", "path": repo["path"]}
            receipts.append({"id": rid, **receipt})
        prepared = stage / "workspace.yml"
        prepared.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
        try:
            WorkspaceManifest.load(prepared)
        except ValueError:
            raise ValueError("invalid workspace paths or dependencies") from None
        (stage / "sources.json").write_text(
            json.dumps({"version": 1, "repositories": receipts}, indent=2) + "\n",
            encoding="utf-8",
        )
        if os.path.lexists(output):
            raise ValueError("output directory already exists")
        stage.rename(output)
    return output / "workspace.yml"
