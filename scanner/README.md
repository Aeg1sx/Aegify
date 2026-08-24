# Aegify Scanner

Alpha-stage white-box application security scanner with repository-aware
program graphs, compiler-index integration, API/runtime attack-surface
evidence, isolated verification, and optional LLM review.

## Quick Start

```bash
pip install aegify-sast
aegify scan ./src --severity high
```

## Features

- Cross-file Call Graph analysis
- Collision-safe multi-repository workspace scans
- Cross-repository and cross-module reachability with fidelity-labeled SCIP,
  exact Maven/Gradle artifact/provider-module, coarse build dependency, call,
  data, framework, API, and runtime edges
- Maven property/dependency-management and Gradle literal/default-version-catalog
  dependency coordinates, promoted to exact selected versions by Gradle lockfiles,
  with unresolved/ambiguous/version-conflict SARIF counters
- Descriptor-safe Java/Kotlin overload resolution across local call graph,
  CHA/RTA, Spring DI, and taint paths, including Kotlin defaults and varargs
- Compiler-classpath bytecode call graph with opcode provenance, direct dispatch,
  class/interface CHA candidates, inherited/default-method deduplication, and
  allocation-aware RTA targets from `NEW` instructions, while preserving CHA
  coverage; LambdaMetafactory/altMetafactory lambda and method-reference targets,
  non-Lambda bootstrap evidence, and unresolved/ambiguous counters
- Exact SCIP package/version ownership and cross-repository resolution with a
  content-addressed persistent import cache and conflict/unresolved counters
- Normalized program graph with branch/loop/switch/when and conservative
  try/catch/finally CFG, call-site-preserving source-bounded call/return ICFG,
  reaching-def DFG, SSA phi, data-state transformation, context-bounded JVM
  source points-to/alias,
  call, taint, and Spring overlays, with bounded callsite-balanced normal and
  declared-exception return queries
- Bounded global taint analysis with flow-sensitive locals, allocation-site
  fields, k=2 call-string contexts, call argument/receiver/scalar-and-object-return
  propagation, returned-object field identity, singleton heap strong updates,
  category-scoped sanitizer state, and a versioned JVM library model pack
- Spring/Kotlin component and `@Bean` DI with qualifier/primary/name/ambiguous
  selection, profile/conditional evidence, exact module/provider-scoped
  cross-repo dispatch, Security, transaction, coroutine/Reactor models, endpoint,
  and Spring Cloud Gateway extraction
- Frontend/Gateway/runtime HTTP call to backend endpoint correlation
- CodeQL/SARIF, Semgrep JSON, and Joern JSONL/GraphSON evidence adapters
- Browser/proxy HAR and OpenTelemetry trace evidence adapters
- Active loopback intercepting proxy with method/path/query/header/body/JSON
  mutation and value-redacted hash evidence
- Digest-pinned isolated `scip-java index` and loopback HTTP verification plans
- Approved no-network Maven/Gradle classpath exporter with deterministic bundle,
  SHA/path/compression revalidation, safe materialization, and bytecode re-import
- Executable YAML rule-schema auditing
- Evidence-bound AI review suggestions that never auto-suppress findings
- Allowlisted read-only AI tools and bounded multi-repository tool orchestration
- Owned-corpus precision/recall/F1 benchmark gates
- SARIF 2.1.0 output
- GitHub PR integration

The alpha does not claim exhaustive source-and-bytecode heap points-to, IFDS/IDE
tabulation, exception-complete interprocedural CFG, or autonomous browser
exploit proof. Every fallback edge remains fidelity-labeled; see the
repository-level readiness assessment before production use.
