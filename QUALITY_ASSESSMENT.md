# Aegify Open-Source Quality Assessment

Assessment date: 2026-08-22

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
| Scanner regression | Pass | 339 passed, 1 skipped |
| Bundled-rule precision | Pass | 17 passed; fallback retention and evidence-only blocking are covered |
| Python quality | Pass | Ruff and strict mypy across 75 source files |
| Rules | Pass | 311 definitions; 303 enabled; 8 explicitly disabled; 980/980 enabled patterns executable; zero audit errors/warnings |
| Packaging | Pass | `aegify_sast-0.1.0-py3-none-any.whl`; isolated `aegify version` smoke |
| Dashboard | Pass | 14 tests, ESLint, TypeScript, and Next production build |
| Dependencies | Pass | npm high-severity audit: zero vulnerabilities |
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
| Aegify self-scan | Pass | 323 medium-or-higher candidates retained as advisory; 45 critical, 167 high, 111 medium; 0 blocking; exit code 0 |

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

Detailed evidence is in [Alpha Completion Audit](docs/project/alpha-completion-audit.mdx),
[Technical Architecture](docs/architecture/technical-architecture.mdx), and
[Rule Authoring](docs/analysis/rule-authoring.mdx).
