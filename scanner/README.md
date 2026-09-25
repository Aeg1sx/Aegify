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
