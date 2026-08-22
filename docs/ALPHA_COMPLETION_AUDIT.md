# Aegify Alpha Completion Audit

Baseline date: 2026-08-22

## Verdict

The open-source alpha implementation scope is present, but this hardening branch
is not yet release-green. Tests cover multi-repository and monorepo
reachability, Java/Kotlin/Spring semantics, Spring Cloud Gateway
transformations, Program Graph queries, frontend-to-backend attack-surface
correlation, normalized rules, external evidence adapters, and bounded
verification harnesses. A separate precision suite retains five failing
regressions for broad race-condition, external API consumption, and ReDoS
fallbacks; they must not be hidden from the release decision.

Colima was started for this audit. Both final images were rebuilt from the
current source and exercised live. Temporary containers and volumes were removed,
and all Colima profiles were returned to their original stopped state.

## Requirement evidence

| Requirement | Implemented evidence | Accuracy boundary |
|---|---|---|
| Rule normalization | Strict schema, duplicate/regex/language checks, partial-pattern execution rejection | 311 definitions; 303 enabled; 8 disabled with reasons; 980/980 enabled patterns executable; zero errors/warnings |
| AST and call graph | tree-sitter language parsers, repository-qualified symbols, call-site-preserving multigraph | Collision and repeated-call regression tests |
| CFG/ICFG | Branch, loop, switch/when, break/continue, conservative try/catch/finally, source and selected bytecode call/return edges | Runtime/implicit exception completeness is a later precision track |
| SSA/DFG | Reaching definitions, phi nodes, def-use and data-state transformation edges | Bounded source representation, not a full Joern-equivalence claim |
| Context reachability | Call-site stack push/pop, recursion/depth/state bounds and explicit exhaustion errors | Default bounds are recorded in evidence |
| Points-to and taint | k=2 JVM source call context, allocation/field identity, receiver/argument/return summaries, strong update for singleton fields | Unified source/bytecode heap and IFDS/IDE are future work |
| JVM library model | Versioned, strict source/sink/propagator/sanitizer pack | Initial high-value model set, not exhaustive ecosystem coverage |
| Multi-repo | Exact SCIP external symbols and package versions; Maven/Gradle provider modules; classpath/bytecode links | Coarse declared-dependency fallback is labeled by fidelity |
| Monorepo | Maven/Gradle module membership and dependency graph; multiple indexes | Custom build logic can require explicit metadata |
| JVM classpath/bytecode | SHA-bound snapshots, safe materialization, module-scoped artifacts, bounded class parsing, CHA/RTA, selected invokedynamic | Ambiguous targets stay unresolved rather than guessed |
| Spring DI | Components, factories, constructor/field injection, qualifier/primary/name/ambiguous resolution, conditional evidence | Actual runtime condition activation is not executed |
| Spring Gateway | YAML and supported Java/Kotlin DSL predicates, filters and path transformations | Dynamic route construction is conservative |
| Frontend surface | fetch/axios-style calls correlated with backend and Gateway paths | Dynamic URL construction may remain unresolved |
| Runtime surface | HTTP, browser, proxy, HAR and OTel observation links | Observation is distinct from exploit proof |
| External tools | SARIF/CodeQL, Semgrep JSON, Joern JSONL/GraphSON | Imports are path-safe and size/count bounded |
| Verification | Digest-pinned Docker, approval, no-network/read-only/cap-drop/resource/time/output controls; loopback HTTP/browser/proxy | Authenticated/TLS/multi-origin policy is post-alpha |
| Dashboard | Authenticated fail-closed production configuration, SARIF ingestion, endpoint and graph views | Auth.js v5 is still a beta dependency |

## Executed release gates

```text
scanner tests:          339 passed, 1 skipped
rule precision tests:   17 passed
ruff:                   passed
mypy --strict:          75 source files passed
rule audit:             311 rules, 303 enabled, 8 disabled,
                        980/980 enabled patterns executable,
                        0 errors, 0 warnings
dashboard tests:        14 passed
dashboard lint:         passed
dashboard build:        passed (Next.js 16.3.1)
dashboard npm audit:    0 vulnerabilities at high threshold
wheel:                  aegify_sast-0.1.0-py3-none-any.whl
isolated wheel smoke:   Aegify v0.1.0
scanner container:      uid/gid 10001, hardened version and clean scan passed
dashboard container:    uid 1001/gid 1001, no build secrets,
                        missing config -> HTTP 500 fail-closed,
                        configured sign-in -> HTTP 200,
                        protected root -> HTTP 307
self-scan:              323 medium-or-higher candidates
                        (45 critical, 167 high, 111 medium)
                        323 advisory, 0 blocking; exit code 0
```

## Evidence states

1. `candidate`: a static rule or imported-tool result that remains advisory.
2. `reachable`: a bounded graph path connects an exposed or calling surface.
3. `observed`: approved runtime evidence exercised the route or code path.
4. `impact_proven`: a separate approved proof demonstrated security impact.

The dashboard and reports must never collapse these states. Gate disposition is
stored separately: advisory findings remain visible, while only supported
semantic evidence may be marked blocking.

## Post-alpha precision track

1. Larger JVM framework and library model corpus with public precision/recall.
2. Maven BOM, convention plugin, and custom catalog resolution.
3. Generic substitution, Kotlin extension semantics, and more bootstrap methods.
4. Unified source/bytecode heap and exception-complete ICFG.
5. IFDS/IDE-style tabulation for selected analyses.
6. Explicit authenticated, TLS, and multi-origin verification policies.
7. Approval-controlled automated impact proof.
