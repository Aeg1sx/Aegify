# Aegify Scanner

The Python analysis engine for Aegify's team self-hosting beta. Analyze source,
retain call/data-flow evidence, export SARIF and optionally review findings with
bounded AI source tools. The proposed first release is `v0.3.0-beta.1`
(Python package `0.3.0b1`).

## Install from source

Requires Python 3.14+ and uv 0.12.18. From the repository root:

```bash
uv sync --locked --project scanner
uv run --project scanner --locked aegify version
uv run --project scanner --locked aegify scan /path/to/repository \
  --no-llm --output json --output-file scan.json
uv run --project scanner --locked aegify agent-run scan.json \
  --mode deep --output-file agent-run.json
```

The scan and default agent command do not call a model. For a packaged wheel,
use the verified assets from a published GitHub release. A GitHub release does
not imply a package is available on PyPI.

## Analysis and review

- Python, JavaScript, TypeScript, Java, Kotlin, Go, Rust and Swift parsing.
- Bounded taint, normalized program graphs, call paths and explicit analysis gaps.
- Repository-qualified workspaces, SCIP import, JVM classpath/bytecode evidence
  and Spring framework models.
- JSON/SARIF output, stable evidence identity, executable YAML rule auditing and
  reproducible case/fixture evaluation.
- Six optional AI agent roles with bounded source list/search/read tools,
  source-hash binding, citations, retained tool evidence and partial-result reporting.

Candidate, reachable, runtime observed and impact proven are separate evidence
states. AI review does not change human triage or establish exploit impact.
The six-role CLI loop writes its artifact at completion; per-turn crash recovery
and live-provider quality acceptance remain open.

The latest retained public OWASP Python evaluation reports precision 68.37% and
recall 49.31% over 1,193 scored case/CWE labels. Another 37 labels are unscored.
It is a public diagnostic corpus, not an independent application holdout or an
accuracy guarantee. Unmodeled frameworks, control flow, reflection and generated
code remain coverage limits.

See the [repository](https://github.com/Aeg1sx/Aegify),
[quality assessment](https://github.com/Aeg1sx/Aegify/blob/main/QUALITY_ASSESSMENT.md),
and [agent contract](https://github.com/Aeg1sx/Aegify/blob/main/docs/concepts/security-agents.mdx)
for evidence, installation and operating boundaries.

### Prepare a multi-repository workspace

From the scanner source directory, prepare the local web, gateway and orders
fixtures alongside a pinned public GitHub repository, then scan the manifest.

```sh
aegify prepare-workspace examples/workspace-sources.yml --output ./prepared-example
aegify scan-workspace ./prepared-example/workspace.yml
```

To prepare and scan in one invocation, run
`aegify scan-workspace examples/workspace-sources.yml --prepare-to ./prepared-example`.
This reads scan settings beside the original manifest. A later scan of the
prepared manifest can supply the same settings file with `--config`.

In each repository entry, use `path` for a local directory or `source: {url,
revision}` for a hosted repository. Supply the full 40-character Git commit
SHA. The output directory must be new. Preparation publishes `workspace.yml`
and `sources.json` together after all sources have been resolved. Local paths,
SCIP indexes and external artifacts remain references to their original paths
relative to the input manifest. Changes to local files affect subsequent scans.
Hosted files are copied from the verified Git tree at the recorded commit.
The receipt includes the provider, URL, commit and tree SHA, byte and file
counts, and counts of skipped symlinks and submodules.

| Provider | HTTPS repository location | Optional secret environment variable |
| --- | --- | --- |
| GitHub.com | `github.com/OWNER/REPO.git` | `AEGIFY_GITHUB_TOKEN` for a token with repository contents read access |
| GitLab.com | `gitlab.com/GROUP/SUBGROUP/REPO.git` | `AEGIFY_GITLAB_TOKEN` for a personal token with `read_repository` |
| Bitbucket Cloud | `bitbucket.org/WORKSPACE/REPO.git` | `AEGIFY_BITBUCKET_TOKEN` for an API token with `read:repository:bitbucket` |
| Azure Repos | `dev.azure.com/ORG/PROJECT/_git/REPO` | `AEGIFY_AZURE_REPOS_TOKEN` for a personal access token with Code Read |

Set private credentials in the calling process or CI secret store. The HTTPS
transport receives a header scoped to the selected repository. Tokens are
excluded from arguments, receipts and diagnostic output. Hosted Git fetching
requires a POSIX environment with system Git and a directly reachable canonical
host. Interactive login, redirects, proxy environment variables and user Git
configuration are disabled. For self-hosted forges, SSH-only repositories or
enterprise authentication that requires a helper, use an existing local checkout.
The example above was exercised against public GitHub. A second preparation
fetched GitLab's nested `gitlab-org/project-templates/express` repository at
`b5c899235f282774e2e5734fe5c1cd0bcb97adee` (11 files) and Bitbucket's
`tutorials/splitpractice` at `e41307a8b2a8e93c700901ca6bbb3e7b79206aad`
(13 files). Azure Repos and private credentials were exercised using local
Git transport fixtures. An anonymous Git probe of the Azure dnceng public
project requested credentials. A provider must allow
fetching the named commit. A missing or inaccessible commit fails preparation.

The preparer reads raw Git blobs and never checks out a working tree. Executable
bits are removed, Git LFS pointer files stay as pointers, and submodules and
symlinks are skipped. Limits are 32 repositories, 25,000 entries per remote,
16 MiB per blob, 128 MiB per Git pack file, 256 MiB of extracted files across
remotes and 120 seconds per Git operation.
