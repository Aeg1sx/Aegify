# Commercial readiness workstream

This is the implementation and acceptance ledger for the 2026-09-24 request.
The product remains alpha until the evidence below supports a narrower, explicit
release contract. Passing existing tests is not a commercial-readiness claim.

## Acceptance work

| Workstream | Required outcome | Acceptance evidence | Status |
|---|---|---|---|
| Scan health | Failed, partial, unsupported and successful analysis are distinguishable in CLI, SARIF, dashboard and CI | Failure injection, truncation controls, upload integration | In progress |
| Evaluation | Order-independent matching, explicit scope, positive/negative cases, per-rule/language/CWE results, uncertainty and held-out evaluation | Versioned source/label digests, independently reviewed labels, regression CI | In progress |
| Analysis fidelity | Accurate parser diagnostics, typed sources/sinks/sanitizers, validated paths, framework and alias models | Supported-stack matrix and positive/negative semantic regression cases | In progress |
| Shared scan service | UI, CLI and CI invoke the same engine and preserve the same evidence | End-to-end scan/upload/review tests and failure recovery | Pending |
| Repository context | Collision-safe multi-repository and monorepo identity, dependencies, snapshots and incremental invalidation | Cross-repository fixtures; incremental/full result equivalence | Pending |
| Rule authoring | Guided templates, schema diagnostics, source/sink/propagation explanations, preview and regression cases | Author a rule, preview matches, export and run it in CI | Pending |
| AI review | Bounded source browsing and evidence tools for threat modeling and supplied-finding review, abstention, triage and remediation advice | Tool-contract tests, source-bound citations, model comparison and repeated-run evaluations | Pending |
| Agent operations | Durable jobs, logs, tool spans, evidence events, cancellation, retry, budgets and cost accounting | Worker interruption/recovery tests and dashboard observation | Pending |
| Provider support | Claude Code and Codex adapters with explicit models, bounded read-only tools and reproducible traces | Local contract tests plus separately recorded live-provider checks | Pending |
| Product experience | Clear analysis scope, uncertainty, repository navigation, data flow/graph views and triage workflow | Browser checks of the complete user flow and accessibility | Pending |
| Open-source evaluation | Pinned Juice Shop, DVWA and other relevant source corpora, with support gaps reported honestly | Static-only runs, scope inventory, reviewed labels and documented results | Pending |
| Efficiency | Fixed-hardware latency/memory/cost baselines, dependency-aware incremental work and cache invalidation | p50/p95 and peak-memory reports; unchanged-result comparison | Pending |
| Reproducibility | Engine/parser/rules/modelpack/config/source/provider manifests and replayable evidence | Clean-environment replay and artifact-digest checks | Pending |
| Enterprise operations | Project roles, service identities, isolation, audit, retention, backups and migration recovery | Authorization integration and operational recovery tests | Pending |
| Dependencies and PRs | Review and resolve the nine open dependency PRs without bypassing unexplained failed checks | Current PR heads, coordinated lockfiles, CI, merge/closure state | In progress |
| Code scanning | Fix real defects; retain or explicitly explain uncertain and governance findings | Fresh analysis on the merged commit and per-alert disposition evidence | In progress |

Dynamic observations and confirmed impact remain separate evidence states. This
workstream implements defensive source analysis and review; it does not add
autonomous exploitation or execute vulnerability payloads against applications.

## Starting evidence

- Base: `main` at `5a1a028f18968193f1b504b6a72de9618647eb62`.
- Selected scanner tests: 163 passed. Dashboard tests: 83 passed.
- `core-v1`: five rules, nine positive findings, TP=9/FP=0/FN=0.
- Additional contract checks found order-dependent scoring, file-only endpoint
  attribution, and a failed scan exiting successfully.
- GitHub: nine open dependency PRs; 541 open code-scanning alerts (535 Aegify,
  six Scorecard). These counts are a starting snapshot, not a triage verdict.
- PRs #24/#27 fail CodeQL; #30/#31/#33/#34 share dependency CI failures;
  #34 also fails the scanner container check. Diagnose before merging.

## Delivery order

1. Repair scan-health, evaluation and evidence contracts, including regression
   tests for the observed defects.
2. Repair dependency/security CI and publish a reviewed foundation change.
3. Connect the common scanner to durable jobs and the product workflow.
4. Add bounded AI source tools, provider contracts, tracing and budgets.
5. Improve rule authoring and graph/data-flow navigation with browser validation.
6. Expand semantic and real-source evaluation; measure efficiency, repeatability
   and end-to-end AI utility on independently labeled data.
7. Complete enterprise operations and verify every acceptance row before any
   commercial-readiness claim.

## Foundation checkpoint: 2026-09-24

Implemented scan health across CLI, JSON/SARIF, GitHub comments, imports and scan
screens; order-independent maximum-cardinality benchmark matching; directed
symbol/range/repository evidence checks; TSX/module-extension parsing; bounded
syntax diagnostics; unsupported-source inventory; parser/content-bound AST
caches; explicit taint resource settings; and coordinated dependency updates.
Absence reconciliation is restricted to recorded files/rules on the default
branch and publishes atomically with the completed import.

Local evidence (remote CI and merge remain separate gates):

- Full scanner suite checkpoint: 448 passed, one skipped, 80.35% coverage.
  Subsequent source-health/parser tests: 36 passed; taint/health tests: 39 passed.
- Dashboard: 85 passed, including a fresh database and transactional absence
  rollback; lint, TypeScript and production build passed.
- Core v1: TP=9, FP=0, FN=0 in five scoped rules. No broad accuracy claim.
- Rule DSL: 303 enabled definitions, 980 patterns, zero strict-audit errors.
- npm audit: zero known vulnerabilities in both updated lockfiles; Python audit:
  zero known vulnerabilities/adverse statuses across 64 packages.
- Supply-chain policy and its three coordinated-update regressions passed.
- Documentation validation, links and accessibility checks passed. Color checks
  retain existing recommendations beyond WCAG AA.
- Real local API uploads preserve completed/partial/failed status with zero
  findings. Browser verification is recorded separately.
- Self-scan: 260 files, 157.2 seconds, 13,626 taint contexts, no reported gaps,
  601 advisory candidates and zero blocking findings. These are candidates,
  not a finding-by-finding security audit or a universal clean bill of health.

The upstream py-tree-sitter 0.26.0 Point attribute regression is tracked at
[upstream issue 500](https://github.com/tree-sitter/py-tree-sitter/issues/500).
Parser diagnostics use tuple access, matching the existing extractor convention.

Pinned source-only Juice Shop and DVWA evaluations are in progress. PHP is not
supported by the current parser contract; DVWA must not receive a whole-project
success claim merely because its JavaScript utilities can be parsed.
