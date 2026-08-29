# Aegify

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Alpha-stage white-box application security platform with repository-aware program graphs, compiler-index integration, API/runtime attack-surface evidence, isolated verification, and optional LLM review.

Official documentation: [Mintlify source](docs/index.mdx) and
[quickstart](docs/quickstart.mdx).

Project policies: [contributing](CONTRIBUTING.md), [security](SECURITY.md),
[governance](GOVERNANCE.md), [support](SUPPORT.md), and
[secrets management](docs/operations/secrets-management.mdx).
[Repository-side security controls](docs/security/repository-security.mdx) document the
branch, tag, review, advisory, and supply-chain settings expected on GitHub.

## Dashboard

![Aegify dashboard overview using demo scan data](docs/assets/aegify-dashboard.png)

_Dashboard preview using demo scan data._

> Aegify now implements a normalized CFG/SSA/DFG security graph with
> call-site-preserving source-bounded interprocedural call/return edges, basic
> context-bounded JVM source points-to/alias overlays, a bounded
> flow/field/allocation-site and k-limited
> call-string-sensitive global taint solver, versioned JVM library summaries,
> SCIP/JVM and Spring models, external-tool adapters, and
> policy-bounded runtime evidence. It does not claim exception-complete
> interprocedural CFG, exhaustive reflection/framework points-to, IFDS/IDE
> tabulation, or autonomous browser exploit proof. See the
> [current readiness assessment](QUALITY_ASSESSMENT.md) before production use.

## Features

- **Multi-language AST parsing** via tree-sitter (Python, JavaScript, TypeScript, Java, Go, Rust, Swift, Kotlin)
- **Collision-safe multi-repository workspaces** with stable repository-qualified symbol IDs
- **Layered semantic graph** with SCIP protobuf-JSON/native CLI import, JVM build discovery, and source-fallback CHA/RTA
- **Context-bounded JVM source points-to** with allocation sites, aliases,
  arguments, receivers, returns, direct calls, k=2 call contexts, and exact
  cross-repository import/provider resolution
- **SCIP package resolver and import cache** with exact scheme/manager/name/version
  coordinates, version-conflict evidence, unresolved counters, and content-addressed shards
- **Overload-safe JVM call identity** with Java/Kotlin source descriptors,
  exact caller ranges, arity/literal/local-variable type scoring, Kotlin default
  parameters and varargs, propagated through CHA/RTA, Spring DI, taint, and SARIF counters
- **Cross-repo and monorepo reachability** through precise SCIP symbols,
  exact Maven/Gradle artifact coordinates resolved to workspace provider modules,
  or explicitly coarse repository/module dependency fallbacks
- **Compiler-classpath bytecode reachability** through strict SHA-256 snapshot
  import, bounded JAR/classfile parsing, exact source-to-bytecode overload
  linking, direct calls, hierarchy-resolved virtual/interface CHA candidates,
  allocation-aware RTA evidence from `NEW` instructions, internal invokes, and
  LambdaMetafactory/altMetafactory `invokedynamic` targets, and declared-exception
  ICFG edges; CHA edges remain available as conservative coverage
- **JVM dependency evidence** from Maven properties/dependency management,
  Gradle literal declarations, default version-catalog aliases/bundles, and
  dependency lockfiles, with dynamic/unresolved/ambiguous/version-conflict counters
- **Normalized program graph** with branch/loop/switch/when and conservative
  try/catch/finally CFG, repeated-call-safe source-bounded ICFG, reaching-def
  DFG, SSA phi, data-state transformation, allocation/alias, call, taint,
  framework, API, and runtime overlays, plus callsite-stack-balanced bounded
  source/bytecode normal and exception-return queries
- **Global taint v2** with flow-sensitive locals, allocation-site object fields,
  k=2 call-string contexts, argument/receiver/scalar-and-object-return propagation,
  receiver-target sinks, returned-object field identity, singleton-allocation field strong updates,
  category-scoped sanitizer state, a strict JVM source/sink/propagator/sanitizer
  model pack, and SCIP-disambiguated cross-repository paths
- **311 YAML rule definitions** with a strict executable-schema gate; 303 are enabled,
  all 980 declared enabled patterns are executable, and 8 unsupported-language
  references are explicitly disabled
- **Spring MVC/Kotlin endpoint extraction** including class and method route composition
- **Spring/JVM framework model v2** for component/`@Bean` factories,
  `@Qualifier`/`@Primary`/name/ambiguous selection, profile/conditional evidence,
  exact module/provider-scoped cross-repo DI, method security, transactions,
  Kotlin suspend, and Reactor continuations
- **Frontend and Spring Cloud Gateway correlation** with file/line evidence and confidence
- **Reproducible evidence contract** with workspace snapshots, analyzer/rule provenance, and stable evidence IDs preserved through SARIF and dashboard ingestion
- **Evidence-gated findings** that retain broad heuristics as candidate/advisory results while only taint or structured semantic evidence can block CI; SARIF and the dashboard preserve both evidence state and gate disposition
- **Evidence-bound AI review** with structured likely-TP/likely-FP/needs-review suggestions, explicit evidence gaps, remediation, and approval-gated owned-fixture proof templates; AI never mutates finding status
- **Allowlisted AI analysis tools** for finding context, call paths, attack surface, workspace summaries, and harness planning, with bounded custom read-only tool registration
- **Persistent finding lifecycle** with stable SARIF fingerprints, new/unchanged/updated/regressed baselines, current-vs-history views, time-bounded triage, and actor-stamped audit events
- **Reproducible precision gates** with owned ground truth, per-rule precision/recall/F1, unmatched evidence, and threshold-based CI exit codes
- **SARIF 2.1.0 output** for GitHub Code Scanning, SonarQube, and VS Code integration
- **API endpoint detection** for Flask, FastAPI, Django, Express, Spring, and Go net/http
- **Web dashboard** with finding triage, call graph visualization, and severity charts
- **DefectDojo integration** for centralized vulnerability management
- **Parallel parsing** with deterministic fallback for restricted CI environments
- **Isolated verification plans** with digest-pinned images, no-network Docker policy, explicit approval, and hashed evidence
- **External analysis adapters** for CodeQL/SARIF, Semgrep JSON, and Joern JSONL/GraphSON
- **Runtime evidence adapters** for browser/proxy HAR, HTTP harness output, and OpenTelemetry traces
- **Isolated compiler indexing** for `scip-java index` with retained, hashed `index.scip` artifacts

## Quick Start

### Install

```bash
cd scanner
pip install -e .
```

### Scan

```bash
# Console output
aegify scan /path/to/code --severity low --no-llm

# SARIF output
aegify scan /path/to/code --output sarif --output-file results.sarif --no-llm

# With LLM verification (requires AEGIFY_ANTHROPIC_API_KEY)
aegify scan /path/to/code --output sarif --output-file results.sarif --llm

# List available rules
aegify rules

# Audit the actual executable YAML rule surface
aegify audit-rules ../rules --json

# Scan several repositories as one workspace
aegify scan-workspace ../aegify-workspace.yml \
  --output sarif --output-file results.sarif \
  --semantic-graph-file semantic-graph.jsonl \
  --program-graph-file program-graph.jsonl

# Add bounded, tool-grounded AI review to a multi-repository scan
aegify scan-workspace ../aegify-workspace.yml \
  --ai-tools --max-ai-findings 50 \
  --output sarif --output-file results.sarif

# Gate a versioned owned benchmark corpus on measured precision and recall
aegify benchmark ../fixtures --ground-truth ../ground-truth.json \
  --min-precision 0.95 --min-recall 0.90 \
  --output-file benchmark-report.json

# Plan compiler-backed Java/Kotlin indexes per repository/build root
aegify index-scip-java ../aegify-workspace.yml \
  --image ghcr.io/scip-code/scip-java@sha256:<digest>

# Plan approved, offline Maven/Gradle classpath export per build root
aegify export-jvm-classpath ../aegify-workspace.yml \
  --image registry.example/aegify-jvm-classpath@sha256:<digest>

# Resolve an isolated verification plan without executing it
aegify verify-plan ../examples/verification-jvm.yml /path/to/repository

# Plan loopback-only HTTP runtime verification
aegify verify-http ../examples/verification-http.yml /path/to/repository

# Plan a loopback-only Playwright journey with external requests aborted
aegify verify-browser ../examples/verification-browser.yml /path/to/repository

# Plan loopback interception with declarative request mutation
aegify verify-proxy ../examples/verification-proxy.yml /path/to/repository
```

### View Results

- **GitHub**: Push SARIF via the included GitHub Action (see CI/CD section)
- **VS Code**: Install the "SARIF Viewer" extension and open `results.sarif`
- **DefectDojo**: Upload via CLI flag `--upload-defectdojo` or the REST API

CI uploads to the dashboard use the `Authorization: Bearer <upload-token>`
header. Keep `AEGIFY_UPLOAD_TOKEN` separate from `AUTH_SECRET`.

## Architecture

```mermaid
flowchart TB
  subgraph Inputs["Workspace inputs"]
    Repositories["Repositories and manifests<br/>multi-repo or monorepo"]
    Compiler["Compiler and build evidence<br/>SCIP · Maven/Gradle · classpath · bytecode"]
    Tools["External analysis evidence<br/>CodeQL · Semgrep · Joern"]
    Runtime["Runtime evidence<br/>HTTP · browser · proxy · HAR · OTel"]
  end

  Identity["Repository-qualified identity<br/>content-addressed workspace snapshot"]
  Parse["Parallel normalized parsing<br/>tree-sitter CST/AST"]
  Semantics["Semantic resolution<br/>JVM/Spring models · CHA/RTA · cross-repo providers"]
  Program["Normalized program graph<br/>call graph · CFG/ICFG · SSA/DFG · points-to"]
  Taint["Global taint and structured rules"]
  Surface["Attack-surface graph<br/>frontend → Gateway → endpoint → finding"]
  Gate{"Evidence gate"}
  Advisory["Candidate / advisory<br/>retained, non-blocking"]
  Blocking["Reachable / blocking<br/>semantic evidence required"]
  Verify["Approved isolated verification<br/>hashed and redacted artifacts"]
  Review["Optional LLM triage<br/>non-authoritative enrichment"]
  Outputs["SARIF · GitHub · Dashboard · DefectDojo"]

  Repositories --> Identity --> Parse --> Semantics --> Program
  Compiler --> Semantics
  Tools --> Program
  Program --> Taint
  Program --> Surface
  Runtime --> Surface
  Taint --> Gate
  Surface --> Gate
  Gate -->|broad or insufficient evidence| Advisory
  Gate -->|taint or structured semantic evidence| Blocking
  Advisory -->|explicit approval| Verify
  Verify --> Gate
  Gate -.-> Review
  Advisory --> Outputs
  Blocking --> Outputs
  Review -.-> Outputs
```

See the [technical architecture](docs/architecture/technical-architecture.mdx)
for graph layers, trust boundaries, and scaling details.

## Supported Languages

| Language | CST/AST | Taint model pack | Heuristic call graph | Endpoint detection |
|----------|:-------:|:--------------------:|:--------------------:|:------------------:|
| Python | Yes | Yes | Yes | Flask, FastAPI, Django |
| JavaScript | Yes | Yes | Partial | Express |
| TypeScript | Yes | Yes | Partial | Express |
| Java | Yes | Yes | Partial | Spring MVC/WebFlux annotations |
| Go | Yes | Yes | Partial | net/http |
| Rust | Yes | Yes | Partial | - |
| Swift | Yes | Yes | Partial | - |
| Kotlin | Yes | Yes | Partial | Spring annotations |

The taint solver is a bounded source analyzer: it is flow-sensitive for locals,
field-sensitive for normalized access paths, allocation-site-sensitive for
tracked objects, and interprocedural across arguments, receivers, scalar returns,
and object returns whose field identity is consumed by the caller. A field write
to one proven allocation is a strong update; ambiguous aliases remain conservative
weak updates.
It separates calls with a bounded two-site call string, includes a source-level
fixed-point JVM points-to overlay, and ships a strict, versioned JVM model pack.
It is not an IFDS/IDE tabulation engine; unmodeled libraries, reflection,
generated code, and runtime framework behavior still depend on conservative
summaries or imported compiler/tool evidence.

## Configuration

Create `.aegify.yml` in your project root:

```yaml
scan:
  languages: [python, javascript, typescript, java, kotlin, go, rust, swift]
  exclude:
    - "tests/**"
    - "vendor/**"
    - "node_modules/**"

rules:
  severity_threshold: medium
  disabled_rules: []

llm:
  enabled: false
  model: claude-opus-5
  token_budget: 100000
  verify_threshold: 0.7

reporting:
  sarif: true
  github_comment: true
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Aegify
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      # Replace the placeholder with a reviewed full commit SHA.
      - uses: Aeg1sx/Aegify@FULL_40_CHARACTER_COMMIT_SHA
        with:
          llm-enabled: "false"
          upload-sarif: "true"
```

## Docker

```bash
# Start dashboard
# First configure AUTH_SECRET, ENCRYPTION_SECRET, an OAuth provider, and the
# dedicated AEGIFY_UPLOAD_TOKEN in a local ignored .env or via Vault.
docker compose up dashboard

# Run a scan
docker compose run scanner scan /scan/target --output sarif --output-file /scan/target/results.sarif --no-llm
```

## Project Structure

```
Aegify/
  scanner/          Python SAST engine
    src/aegify/    Core scanner package
      scanner/          AST parser, call graph, dataflow, engine
      ir/               CFG/SSA/DFG/points-to program graph and queries
      semantic/         SCIP import/index plan, JVM build/type/module analysis
      framework/        Spring DI/security/transaction/reactive models
      adapters/         CodeQL/SARIF, Semgrep, Joern imports
      runtime/          HTTP/HAR/OpenTelemetry evidence imports
      harness/          isolated build/HTTP verification and Docker executor
      rules/            Built-in AST rules + YAML rule loader
      reporter/         SARIF, GitHub, DefectDojo reporters
      llm/              LLM verification client and prompts
      quality/          Ground-truth precision and recall gates
      storage/          SQLite, PostgreSQL, S3 backends
    tests/            Test suite (pytest)
  dashboard/        Next.js web dashboard
    src/app/          Pages and API routes
    src/components/   UI components (shadcn/ui)
    src/lib/          Prisma client, utilities
    prisma/           Schema and migrations
  docs/             Mintlify documentation, English and Korean navigation
  rules/            YAML rule definitions (OWASP Top 10, API, mobile)
  .github/          CI/CD workflows
```

## Development

```bash
# Install with dev dependencies
cd scanner
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check src/ tests/

# Type check
mypy src/aegify/

# Verify the rule DSL and bundled rules
aegify audit-rules ../rules --strict

# Validate and preview the Mintlify documentation
cd ../docs
npm ci --ignore-scripts
npm run check
npm run dev
```

For hosted documentation, connect this repository in Mintlify and set the
monorepo documentation path to `/docs`. Keep `main` as the production branch;
pull-request previews should be built from the same locked dependencies and
`docs.json` navigation used by CI.

## Technical Documentation

- [Official documentation home](docs/index.mdx)
- [Technical architecture and roadmap](docs/architecture/technical-architecture.mdx)
- [SCIP/JVM semantic-analysis contract](docs/analysis/semantic-analysis.mdx)
- [Isolated verification-harness contract](docs/verification/harness.mdx)
- [External and runtime adapter contracts](docs/integrations/external-runtime-adapters.mdx)
- [Rule authoring and normalization contract](docs/analysis/rule-authoring.mdx)
- [Open-source readiness assessment](QUALITY_ASSESSMENT.md)
- [Alpha requirement-by-requirement completion audit](docs/project/alpha-completion-audit.mdx)
- [Threat model and deployment boundaries](docs/security/threat-model.mdx)
- [Data, privacy, telemetry, and retention policy](docs/security/privacy.mdx)
- [Security and coordinated disclosure policy](SECURITY.md)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Run tests and linting before committing
4. Submit a pull request

## License

MIT
