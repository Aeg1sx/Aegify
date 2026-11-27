# Aegify Scanner

The Python analysis engine for Aegify's team self-hosting beta. Analyze source,
retain call/data-flow evidence, export SARIF and optionally review findings with
bounded AI source tools. The proposed first release is `v0.3.0-beta.1`
(Python package `0.3.0b1`).

## Install from source

Requires Python 3.14+ and uv 0.13.9. From the repository root:

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
| Azure Repos | `dev.azure.com/ORG/PROJECT/_git/REPO` | `AEGIFY_AZURE_REPOS_TOKEN` for a personal access token with Code Read, or `AEGIFY_AZURE_REPOS_ENTRA_TOKEN` for a Microsoft Entra access token for Azure DevOps |

Set private credentials in the calling process or CI secret store. The HTTPS
transport receives a header scoped to the selected repository. Tokens are
excluded from arguments, receipts and diagnostic output. Hosted Git fetching
requires a POSIX environment with system Git and a directly reachable canonical
host. Interactive login, redirects, proxy environment variables and user Git
configuration are disabled. Use a local checkout for SSH-only repositories or
authentication that requires an interactive helper.

For GitHub Enterprise Server and GitLab Self-Managed, define trusted hosts in
the environment of the process running `prepare-workspace` or `scan-workspace`.
The manifest uses the same `source.url` and full `source.revision` fields.
Each entry trusts the complete HTTPS authority. Use a hostname dedicated to
the Git service and include its port when it uses a non-default port.

```sh
export AEGIFY_WORKSPACE_GIT_HOSTS='[
  {"host":"code.example.com","provider":"github","token_env":"AEGIFY_WORKSPACE_TOKEN_CODE"},
  {"host":"git.example.com:8443","provider":"gitlab"}
]'
```

Supply the named token through the runner's secret store. Choose a name
beginning with `AEGIFY_WORKSPACE_TOKEN_` for each private host. An entry
without `token_env` uses an anonymous fetch. Custom hosts never inherit the
cloud provider tokens. Set `AEGIFY_WORKSPACE_GIT_CA_FILE` to the absolute
path of a PEM trust bundle when the server uses an internal certificate
authority. This setting applies to the configured enterprise hosts. The
receipts identify the instance URL, provider, commit and tree SHA.
[GitHub Enterprise HTTPS remotes](https://docs.github.com/en/enterprise-server@3.19/get-started/git-basics/about-remote-repositories) · [GitLab HTTPS cloning](https://docs.gitlab.com/topics/git/clone/)

For Azure Repos, you can paste the HTTPS clone URL from the repository.
Aegify accepts a matching `ORG@dev.azure.com/ORG` organization hint and the
older `ORG.visualstudio.com/PROJECT/_git/REPO` address, including its
`/DefaultCollection/PROJECT/_git/REPO` form. Git fetches from
`dev.azure.com` and the receipt records that canonical URL. If both Azure
tokens are set, Aegify uses the Entra access token. See
[Microsoft's Azure Repos authentication guide](https://learn.microsoft.com/en-us/azure/devops/repos/git/auth-overview?view=azure-devops).

To exercise all four public providers together, run the following command
from the scanner source directory with a new output directory.

```sh
aegify scan-workspace examples/provider-workspace/workspace.yml \
  --prepare-to ./prepared-providers -o json -f provider-review.json
```

The example fetches four pinned public Git trees and reads a local Spring
Cloud Gateway and Kong configuration. In `provider-review.json`, the expected
owners in `gateway_inventory.files[].routes[]` are GitHub for `accounts`,
GitLab for `orders`, Bitbucket for `catalog` and Azure for `wiki`. The
service names in this example are fixtures. Private authentication was tested
with synthetic credentials and local transport fixtures. A provider must
allow fetching the named commit. A missing or inaccessible commit fails
preparation.

The preparer reads raw Git blobs and never checks out a working tree. Executable
bits are removed, Git LFS pointer files stay as pointers, and submodules and
symlinks are skipped. Limits are 32 repositories, 25,000 entries per remote,
16 MiB per blob, 128 MiB per Git pack file, 256 MiB of extracted files across
remotes and 120 seconds per Git operation.
