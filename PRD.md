# Aegify Product Requirements

Status: open-source alpha
Document baseline: 2026-08-22

## 1. Product summary

Aegify is an evidence-first white-box application security platform. It combines
static code analysis, semantic code intelligence, framework-aware reachability,
attack-surface correlation, and policy-controlled runtime verification. The
alpha is designed for self-hosted use across monorepos and related repositories,
with first-class support for Java, Kotlin, Spring, and Spring Cloud Gateway.

Aegify does not treat an LLM opinion as proof. Every finding carries code,
graph, runtime, or external-tool provenance, and the product distinguishes a
static candidate from observed reachability and exploit impact proof.

## 2. Goals

- Resolve symbols and reachability across repositories and monorepo modules.
- Model Java/Kotlin call semantics, Spring dependency injection, and Gateway
  route transformations without silently guessing ambiguous targets.
- Correlate frontend calls, public Gateway routes, backend endpoints, static
  findings, and optional runtime observations into one attack-surface view.
- Provide normalized, auditable rule authoring with a strict zero-debt gate.
- Import and preserve evidence from SARIF/CodeQL, Semgrep, Joern, HTTP, browser,
  proxy, HAR, and OpenTelemetry sources.
- Run verification only through explicit, bounded, isolated policies.
- Ship as a secure open-source project with reproducible CI, dependency and
  secret scanning, signed release provenance, and documented governance.

## 3. Non-goals for alpha

- Claiming parity with a fully autonomous exploitation platform.
- Treating heuristic repository fallback as compiler-precise SCIP evidence.
- Exhaustive IFDS/IDE analysis or a unified source-and-bytecode heap model.
- Arbitrary multi-origin, authenticated, or TLS interception by default.
- Automatically claiming exploitability from a static source-to-sink path.

## 4. Primary users

- Application-security engineers triaging large JVM estates.
- Product-security teams maintaining related service repositories.
- Security researchers writing and validating reusable rules.
- Developers reviewing how a frontend or public route reaches vulnerable code.
- Open-source maintainers who need transparent, reproducible evidence.

## 5. Core workflows

### 5.1 Workspace analysis

Users define repositories, modules, dependency relations, SCIP indexes, build
artifacts, and optional runtime evidence in a workspace manifest. Aegify assigns
repository-qualified identities, calculates a deterministic workspace snapshot,
and analyzes each repository without collapsing same-named symbols.

### 5.2 Cross-repository reachability

Aegify uses the highest-fidelity evidence available:

1. exact SCIP symbol and package-version relations;
2. Maven/Gradle artifact-to-workspace-provider resolution;
3. module-scoped classpath and bytecode call evidence;
4. declared repository dependency fallback, explicitly labeled as coarse.

Version conflicts, ambiguous providers, unresolved symbols, and bounded-analysis
limits remain visible in output. They are not converted into guessed edges.

### 5.3 JVM and Spring analysis

The scanner parses Java and Kotlin, models overloads and type hints, builds
source and bytecode call relations, applies conservative CHA and allocation-aware
RTA, and recognizes selected invokedynamic lambda and method-reference targets.

Spring analysis covers components, constructor and field injection, `@Bean`
factories, qualifiers, primary providers, injection names, conditional evidence,
cross-module providers, selected security guards, transaction proxies, suspend
functions, and Reactor flows. Unknown runtime condition values remain conditional.

### 5.4 Attack-surface correlation

The attack-surface model links:

- frontend `fetch` and axios-style calls;
- Spring MVC/WebFlux and Kotlin endpoints;
- Spring Cloud Gateway YAML and supported DSL routes;
- path rewrites, prefix stripping, method predicates, and filters;
- static findings and taint paths;
- HTTP, browser, proxy, HAR, and trace observations.

Every link preserves source file, line, repository, module, match kind,
confidence, and evidence provenance. The UI must show whether a backend endpoint
is called by known frontend code and whether it is exposed through a public
route; absence of evidence must not be presented as proof of no caller.

### 5.5 Rule authoring

Rules use a normalized YAML contract with stable AEG-prefixed IDs, severity,
language scope, executable patterns or taint declarations, defense patterns,
and remediation text. Strict audit rejects unknown fields, invalid regular
expressions, duplicate IDs, unsupported-only languages, rules with no executable
detector, and partially non-executable pattern sets. Reference-only rules must be
explicitly disabled with a reason.

### 5.6 Verification

Verification plans are declarative and approval-controlled. Docker execution is
digest-pinned, network-restricted, read-only where possible, capability-dropped,
resource-bounded, timed out, and limited by argument allowlists. HTTP and browser
runners are loopback-only by default. Proxy mutation redacts values and stores
hashes rather than credentials or full sensitive bodies.

## 6. Functional requirements

### 6.1 Parsing and code identity

- Incremental-friendly tree-sitter parsing for supported languages.
- Repository, module, file, symbol, and call-site qualified identifiers.
- Collision-safe handling of same-named symbols across repositories.
- Deterministic content and workspace snapshots.

### 6.2 Program Graph

- AST-derived structure and call graph edges.
- CFG for branches, loops, switch/when, break/continue, and conservative
  try/catch/finally behavior.
- Source-bounded ICFG call and return edges with call-site identity.
- Context-balanced bounded path and reachability queries with explicit limit
  exhaustion errors.
- Reaching definitions, SSA phi nodes, def-use, data-state transformations,
  and typed semantic overlays.

### 6.3 Data flow

- Flow-sensitive local propagation and field paths.
- Allocation-site object identity and bounded call-string context.
- Argument, receiver, scalar return, and selected object-return summaries.
- Source, sink, propagator, and sanitizer library models.
- Negative tests for caller isolation and safe overwrites.

### 6.4 Interchange

- SARIF 2.1.0 export and import with Aegify provenance extensions.
- Bounded import for Semgrep JSON and Joern JSONL/GraphSON.
- SCIP import, package/version resolution, shard caching, and JVM index planning.
- Runtime evidence contracts for HTTP, browser, proxy, HAR, and OpenTelemetry.

### 6.5 Dashboard

- Authenticated production operation with independent auth and encryption secrets.
- Valid HTTP(S) `AUTH_URL` origin and a complete OAuth provider in production.
- Dedicated bearer token for CI uploads.
- SARIF ingestion, scans, findings, endpoint inventory, graph, rule, and settings UI.
- Fail closed when required production security configuration is absent.

### 6.6 CLI

- `aegify scan`, workspace scanning, pull-request scanning, rule audit, adapter
  import, index planning, harness execution, and version/help commands.
- Stable nonzero exits for invalid input, policy rejection, and configured
  severity thresholds.
- Machine-readable SARIF and JSON alongside human-readable output.

## 7. Security and privacy requirements

- No committed `.env`, Vault token, database, build output, or analysis artifact.
- Secrets injected through environment variables or Vault Agent templates.
- Production services run as non-root with dropped capabilities and
  `no-new-privileges`; containers use read-only roots where practical.
- External paths, archives, imports, and artifacts are bounded and path-safe.
- Runtime evidence minimizes and redacts headers, cookies, query values, and bodies.
- LLM calls are optional and must receive bounded, redacted context.

## 8. Open-source requirements

- Apache-2.0 license, contribution guide, code of conduct, governance, support,
  security policy, private vulnerability reporting, and CODEOWNERS.
- Pull-request review, code-owner review, resolved conversations, linear history,
  signed commits, and required CI checks on `main`.
- Full-SHA-pinned third-party Actions with least-privilege permissions and
  hardened runners.
- Dependabot for Python, npm, Actions, and each Dockerfile location.
- CodeQL, dependency review, Gitleaks, OpenSSF Scorecard, and zizmor gates.
- Release SBOM, artifact attestation, checksums, and protected version tags.

## 9. Alpha acceptance criteria

- All Python tests pass with at least 60% measured coverage.
- Ruff and strict mypy pass.
- Every enabled rule and every declared pattern is executable; audit has zero
  errors and zero warnings.
- Dashboard tests, ESLint, production build, and high-severity npm audit pass.
- Scanner wheel installs in an isolated environment and exposes `aegify`.
- Scanner and dashboard images build and pass non-root, fail-closed, and hardened
  runtime smoke tests.
- Secret and workflow security scans return zero findings.
- Public documentation is English-first and describes limitations accurately.

## 10. Post-alpha precision milestones

1. Larger JVM library-model coverage and public precision/recall corpora.
2. Maven BOM, convention-plugin, and custom version-catalog resolution.
3. Generic substitution, Kotlin extension semantics, and broader bootstrap models.
4. Unified source/bytecode heap propagation and exception-complete ICFG.
5. IFDS/IDE-style tabulation for selected high-value analyses.
6. Explicitly authorized authenticated, TLS, and multi-origin verification.
7. Automated impact proof with a separate approval and evidence state.
