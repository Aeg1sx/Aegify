# Aegify Open-Source Quality Assessment

Assessment date: 2026-09-04

## Decision

The open-source alpha architecture and evidence-gating policy are implemented.
Aegify has executable multi-repository and monorepo
identity, cross-repository reachability, JVM and Spring semantic models,
frontend/Gateway/backend/runtime attack-surface correlation, a normalized rule
contract, external evidence adapters, and policy-controlled verification. Broad
fallbacks are retained as candidate/advisory results. Taint and normalized
structured evidence are the only default paths to a CI-blocking finding.

This decision does not describe Aegify as a fully autonomous exploitation
platform. Static candidates, graph reachability, runtime observations, and
exploit impact proof are separate evidence states.

## Verified gates

| Area | Result | Evidence and boundary |
|---|---:|---|
| Scanner regression | Pass | 407 passed, 1 skipped; 79.78% measured line coverage |
| Bundled-rule precision | Pass | 18 passed; fallback retention and evidence-only blocking are covered |
| Owned precision corpus | Pass | `core-v1`; 5 scoped taint rules, 9 positive findings plus paired negative controls; TP 9, FP 0, FN 0; source and manifest SHA-256 recorded |
| Python quality | Pass | Ruff and strict mypy across 79 source files |
| Rules | Pass | 311 definitions; 303 enabled; 8 explicitly disabled; 980/980 enabled patterns executable; zero audit errors/warnings |
| Packaging | Pass | v0.2.0 reproducible sdist-to-wheel build; 58 bundled rule files; isolated `aegify version` and rule-load smoke |
| Dashboard | Pass | 25 tests, ESLint, TypeScript, and Next production build |
| Dependencies | Pass | uv/OSV audit: 65 packages with zero known vulnerabilities; dashboard/docs npm high-severity audits: zero; registry signatures verified |
| Documentation | Pass | Mintlify schema/build validation, anchors/links/redirects/snippets, accessibility, and locked dependency audit |
| Containers | Pass | Scanner and dashboard images built; non-root users; read-only/cap-drop/no-new-privileges smoke; dashboard fail-closed without production secrets |
| Cross-repo semantics | Implemented | Exact SCIP/package path, Maven/Gradle provider resolution, module classpath/bytecode, labeled coarse fallback |
| Monorepo semantics | Implemented | Maven/Gradle module membership and dependencies; multiple SCIP indexes |
| JVM semantics | Implemented | Descriptor-aware overloads, CHA/RTA, bounded bytecode import, lambda/method-reference evidence |
| Spring semantics | Implemented | DI candidates, qualifiers, primary/name resolution, factories, conditional evidence, cross-module scope |
| Attack surface | Implemented | Frontend calls, Gateway transformations, backend endpoints, findings, and runtime evidence |
| Program Graph | Implemented | CFG/ICFG/SSA/DFG/data-state overlay with bounded context-balanced queries |
| Data flow | Implemented | k=2 source points-to and bounded global taint with field/object/call context |
| External evidence | Implemented | SARIF, Semgrep, Joern, SCIP, HTTP, browser, proxy, HAR, OTel |
| Supply-chain CI | Pass | SHA-pinned Actions, least privilege, hardened runners, CodeQL, dependency review, Gitleaks, Scorecard, zizmor, SBOM and attestations |
| Finding lifecycle | Implemented | Persistent scan history, stable fingerprints, current occurrence boundary, baseline state, expiring triage, audit events |
| AI review boundary | Implemented | Structured suggestions, no implicit status mutation, allowlisted read-only tools, prompt-injection boundary, secret redaction, owned-fixture proof templates |
| Precision gate | Implemented | Owned ground-truth precision/recall/F1 report with per-rule and unmatched evidence, threshold exit code |
| Aegify self-scan | Pass | 356 medium-or-higher candidates retained as advisory; 53 critical, 179 high, 124 medium; benchmark fixtures excluded; 0 blocking; exit code 0 |

## Known precision limits

- Candidate results still require human or LLM review and are not proof of
  reachability or exploitability.
- The source and bytecode heaps are not yet one exhaustive points-to domain.
- IFDS/IDE tabulation and exception-complete interprocedural modeling remain future work.
- Active Spring profile/property/custom condition evaluation is conservative.
- Compiler-precise SCIP evidence depends on an available language index; fallback
  dependency edges are clearly labeled and lower fidelity.
- Browser and proxy verification is loopback-oriented. Authenticated, TLS, and
  multi-origin testing requires a future explicit policy tier.
- A runtime observation is not automatically exploit impact proof.
- AI confidence is not measured scanner precision and never authorizes status
  changes or proof execution.
- The `core-v1` 100% result applies only to its five declared rules and exact
  digest-bound owned corpus. It is not a whole-product or real-world prevalence
  estimate.

Detailed evidence is in [Alpha Completion Audit](docs/project/alpha-completion-audit.mdx),
[Technical Architecture](docs/architecture/technical-architecture.mdx), and
[Rule Authoring](docs/analysis/rule-authoring.mdx).
