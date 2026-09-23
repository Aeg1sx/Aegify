# Commercial readiness workstream

This is the implementation and acceptance ledger for the 2026-09-24 request.
The product remains alpha until the evidence below supports a narrower, explicit
release contract. Passing existing tests is not a commercial-readiness claim.

## Release priority

The user selected team self-hosting first: one internal installation, project roles,
CI identities and the common scan workflow. Prioritize installation and recovery,
project authorization, project-bound CI uploads and durable workers before hosted
multitenancy or billing. Source tools and AI evidence must obey the same project
permissions and immutable source snapshots.

## Acceptance work

| Workstream | Required outcome | Acceptance evidence | Status |
|---|---|---|---|
| Scan health | Failed, partial, unsupported and successful analysis are distinguishable in CLI, SARIF, dashboard and CI | Failure injection, truncation controls, upload integration | In progress |
| Evaluation | Order-independent matching, explicit scope, positive/negative cases, per-rule/language/CWE results, uncertainty and held-out evaluation | Versioned source/label digests, independently reviewed labels, regression CI | In progress |
| Analysis fidelity | Accurate parser diagnostics, typed sources/sinks/sanitizers, validated paths, framework and alias models | Supported-stack matrix and positive/negative semantic regression cases | In progress |
| Shared scan service | UI, CLI and CI invoke the same engine and preserve the same evidence | End-to-end scan/upload/review tests and failure recovery | In progress |
| Repository context | Collision-safe multi-repository and monorepo identity, dependencies, snapshots and incremental invalidation | Cross-repository fixtures; incremental/full result equivalence | Pending |
| Rule authoring | Guided templates, schema diagnostics, source/sink/propagation explanations, preview and regression cases | Author a rule, preview matches, export and run it in CI | Pending |
| AI review | Bounded source browsing and evidence tools for threat modeling and supplied-finding review, abstention, triage and remediation advice | Tool-contract tests, source-bound citations, model comparison and repeated-run evaluations | In progress |
| Agent operations | Durable jobs, logs, tool spans, evidence events, cancellation, retry, budgets and cost accounting | Worker interruption/recovery tests and dashboard observation | In progress |
| Provider support | Claude Code and Codex adapters with explicit models, bounded read-only tools and reproducible traces | Local contract tests plus separately recorded live-provider checks | Pending |
| Product experience | Clear analysis scope, uncertainty, repository navigation, data flow/graph views and triage workflow | Browser checks of the complete user flow and accessibility | Pending |
| Open-source evaluation | Pinned Juice Shop, DVWA and other relevant source corpora, with support gaps reported honestly | Static-only runs, scope inventory, reviewed labels and documented results | Pending |
| Efficiency | Fixed-hardware latency/memory/cost baselines, dependency-aware incremental work and cache invalidation | p50/p95 and peak-memory reports; unchanged-result comparison | Pending |
| Reproducibility | Engine/parser/rules/modelpack/config/source/provider manifests and replayable evidence | Clean-environment replay and artifact-digest checks | Pending |
| Enterprise operations | Project roles, service identities, isolation, audit, retention, backups and migration recovery | Authorization integration and operational recovery tests | In progress |
| Dependencies and PRs | Review and resolve the nine original dependency PRs and the recorded follow-up updates without bypassing unexplained failed checks | Current PR heads, coordinated lockfiles, CI, merge/closure state | Complete for the listed PRs |
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
  findings. Isolated headless Chrome verified all three detail screens, scan
  history and the concrete partial-analysis diagnostic.
- Self-scan: 260 files, 157.2 seconds, 13,626 taint contexts, no reported gaps,
  601 advisory candidates and zero blocking findings. These are candidates,
  not a finding-by-finding security audit or a universal clean bill of health.

The upstream py-tree-sitter 0.26.0 Point attribute regression is tracked at
[upstream issue 500](https://github.com/tree-sitter/py-tree-sitter/issues/500).
Parser diagnostics use tuple access, matching the existing extractor convention.

Pinned source-only Juice Shop and DVWA smoke evaluations are recorded in
`scanner/benchmarks/real-source-v1/results.json`: Juice Shop analyzed 309 files
with 52 omitted findings and two unsupported shell files; DVWA analyzed nine
utility files and reported 168 in-scope unsupported PHP files. Both returned
partial/exit 3. Labels remain unreviewed and all accuracy metrics are null.

Foundation PR #35 merged at `01fe502484834714e4ddb5f5d9ec8897f56c64be` with a
valid GitHub signature after every required check, CodeQL and self-scan passed on
head `5fb28671d0d085180367d4d9cd2d23abd2d5c4d3`. Original dependency PRs #24,
#25, #26, #27, #28, #30, #31, #33 and #34 are closed/superseded. The immediate
post-merge Dependabot snapshot has zero open vulnerability alerts. New dependency
PRs #36 and #37 are separate updates and require their own review. Code-scanning
candidates still need per-alert triage; no mass dismissal occurred.

## Team access and CI checkpoint: 2026-09-24

Implemented project viewer/triager/maintainer/admin roles, exact operator-owned
workspace administrator admission, scoped lists and aggregations, object checks
on findings/graphs/endpoints/jobs, same-origin mutations, and private/no-store
responses. Shared integration settings and rule management require a workspace
administrator. Finding filter labels are derived only from readable findings.
Legacy project owners receive admin membership during migration; unowned projects
and unlinked scans stay accessible to workspace administrators for recovery.

Project administrators can manage existing admitted accounts and create, inspect
and revoke project-bound upload credentials. Credentials expire within 90 days,
have only scan:upload scope, and store hashes; raw credentials appear once.
The dashboard, production HTTP tests and scanner CLI exercise the same upload
route. CLI delivery uses HTTPS or loopback, rejects redirects, bounds responses
and returns exit 4 on failure. Legacy environment credentials require an explicit
project binding. Member/service uploads cannot overwrite shared rule definitions.
Membership, token, project, settings and import changes produce audit records;
final import status, absence reconciliation and its audit event commit together.

Verified locally:

- Scanner suite: 460 passed, one skipped; Ruff and strict mypy passed.
- Dashboard suite: 87 passed, including fresh/legacy migration, immediate role
  revocation, last-admin preservation and audit-failure transaction rollback.
- Production build, TypeScript, ESLint and supply-chain policy passed.
- 65 real production HTTP/CLI checks with independent synthetic accounts covered
  cross-project reads and writes, filtered counts, direct IDs, CSRF, token scope,
  partial-report delivery, credential revocation and disabled accounts.
- Isolated Chrome exercised member grant, one-time token issuance and revocation,
  viewer restrictions, project selection during upload and the partial-analysis
  banner. Browser requests were restricted to the local test origin.
- Documentation, link and accessibility checks passed, retaining the existing
  color recommendations beyond the minimum AA checks.

The default local Docker daemon is unavailable. Remote CI passed the new named
volume check, including non-root initialization and a persisted project after
container restart. PR #42's first self-scan identified two blocking candidates:
an HTTP client's `.open()` misclassified as a filesystem sink, and the test
harness accepting an environment-selected executable. Exact Python file-open
models now distinguish HTTP/UI methods, with eight positive/negative/bounded
regressions; the optional CLI test uses the repository's fixed virtualenv path.
The updated local self-scan completed without blocking findings or analysis gaps;
all 468 scanner tests passed (one skipped), 65 production HTTP/CLI checks passed,
and type/lint checks passed. All required remote CI, CodeQL and self-scan checks
passed on head `f27de260b2597e95dda05e51abb65247dd39f29a`. PR #42 merged at
`95f52fc79fbeef9fbb7e956d73540cc19e653c78` with a verified GitHub signature.
This checkpoint does not establish live SSO, production deployment, durable scan
workers, backups/restore drills, retention, immutable external audit storage, or
commercial detection accuracy. Those acceptance rows remain open.

Post-foundation code-scanning snapshot: 601 Aegify candidates and five Scorecard
alerts remain open. Removing result caps intentionally retained additional
candidates; the counts are not a precision or security verdict.

## Durable source worker checkpoint: 2026-09-24

Connected project scans now queue the same Python SAST engine used by the CLI.
Saved jobs use renewable leases, fenced writes, commit pinning, encrypted source
snapshots, bounded retry, cancellation and project-permission rechecks. Artifact
publication is one transaction shared with CI/browser uploads. Late failures roll
back findings, identities, graphs, endpoints, absence updates and final job state.
Older scan requests cannot replace a newer published baseline.

The worker uses bundled rules and explicit configuration, passes no repository
credentials to the Python child, and does not execute source, install dependencies
or load repository rules. Provider retrieval, source bytes, taint contexts, child
output and elapsed time are bounded. Resource limits and unsupported languages
remain partial results. The UI exposes queue state, activity, commit and digests,
with maintainer-only cancellation and retry. Docker Compose adds a non-root,
read-only worker using the dashboard's local SQLite volume.

Local checkpoint: 480 scanner tests passed (one skipped), 94 dashboard tests passed
including real Python analysis and cancellation, and type/lint/production-build
checks passed. Publication tests inject late artifact errors, stale worker leases,
revoked access and out-of-order completion. Native process recovery and encrypted
source reuse are also covered. The production server passed 82 HTTP/CLI checks;
isolated Chrome verified queue, cancellation, retry and viewer restrictions.
The first worker self-scan analyzed 284 files in 193.54 seconds, with 694 advisory
candidates, no blocking findings and no analysis gaps.

A two-client contention check exposed SQLite deferred-transaction conflicts.
Startup now enables WAL, and write transactions retry only the pinned adapter's
busy errors, with four bounded attempts and jitter. The concurrent-claim regression
requires both calls to settle successfully and exactly one lease to be issued.
The final local self-scan analyzed 286 files in 201.75 seconds with 694 advisory
candidates, zero blocking findings and no analysis gaps. The final production
HTTP/browser rerun passed all 82 checks.
The first Linux worker check exposed Node's missing `libatomic.so.1` runtime
dependency in the Python base image. The runner now installs `libatomic1` and
checks both runtime entry points as UID 1001 during the image build.
All required CI, CodeQL and self-scan checks passed on final head
`dc0dbdb7e55614a189a75c967db6da9f73c51a9d`. The Linux image passed 12 offline
worker/import/provider checks, fresh migrations, database persistence across a
dashboard restart, and recovery/publication by a separate worker process without
network access. PR #43 merged at `b317be9536214e9508b3e587aa17fadea7510f9f`
with a verified GitHub signature.

This worker phase covers static source scans. Durable AI review jobs, independently
reviewed accuracy labels, private forge connectors, live SSO, operator deployment,
backup/restore and full retention acceptance remain open. GitHub.com/GitLab.com
connectors select source/config files; other forges can use project-bound CI uploads.

## Coordinated dependency follow-up: 2026-09-24

Follow-up PRs #36–#41 propose uv 0.12.18, CodeQL action 4.38.0, zizmor action
0.6.4, harden-runner 2.21.1, setup-uv 10.1.0, lucide-react 1.46.0 and
@types/node 26.6.1. The prepared combined change retains exact hashes and updates
all coupled uv image, CI and project requirements. PR #36's observed policy and
container failures both came from updating its image without the exact required
uv version; neither gate is relaxed.

Official action tags were resolved to the proposed commits. An isolated uv
0.12.18 lock check passed; the host installation was unchanged. A fresh locked
npm install, audit (zero reported vulnerabilities), 94 dashboard tests, 82
production HTTP/CLI checks, TypeScript, ESLint, production build, supply-chain
policy and four policy regression tests passed locally. All required remote CI,
container checks, CodeQL and self-scan passed on head
`74512e467e4db0115abeecd84bc7d43c0acfda55`. PR #44 merged at
`59befc40f0171255a6bdfffb1b587d8fff68e9dc` with a valid GitHub signature.
Follow-up PRs #36–#41 were closed as superseded, with the merge and verification
record linked. This closes the listed dependency updates, not future updates.

The latest main-branch code-scanning snapshot before this dependency follow-up has
679 Aegify candidates and five Scorecard alerts. Their individual disposition
remains separate from passing CI; no bulk dismissal was performed.

## AI path evidence follow-up: 2026-09-24

The call-path tool previously declared a path complete whenever a list of steps
existed. It now shares a structural evidence check with the agent trace: matching
entry handler/repository/range, explicit symbols and directed links, and the full
finding range within the sink's repository. Legacy and disconnected paths remain
incomplete. The 100-step limit produces an explicit gap and truncation flag in
both the tool result and agent trace. Static completeness has no runtime-proof
effect.

Local verification: 28 focused AI/tool tests and 488 full scanner tests passed
(one skipped), with Ruff, strict mypy across 88 source files and documentation
checks passing. The regressions cover missing/mismatched identities, broken and
unfinished edges, entry and sink ranges, and bounded output for a 100,000-step
input. All required CI, container checks, CodeQL and self-scan passed on head
`bfd6f36902f32b2449cb43032476c325d82c1d3b`. PR #45 merged at
`3d024aaf0db464978d0cf685ecfe890873460ef0` with a verified GitHub signature.
The post-merge Dependabot snapshot has zero open vulnerability alerts.

## Bounded AI source review: 2026-09-24

The workspace reviewer now has an iterative read-only source loop. It captures
only scanner-admitted files whose bytes match their parser digest, with explicit
file/byte bounds, repository namespaces and descriptor-based link rejection.
In-memory list/read/literal-search/declaration tools return bounded evidence and
executor-issued source references. Model-selected references must exist in tool
results and cover the finding's repository and range before a non-abstaining
suggestion is accepted. Budget exhaustion and unsupported citations retain
`needs_review`; no workflow or runtime evidence state is promoted.

SARIF carries tool rounds, timings, cache reuse, arguments/result hashes, source
references and prompt/source-manifest digests. The dashboard exposes retained
code and tool activity. Workspace token usage is now included in reporting, and
AI remediation suggestions no longer overwrite scanner-authored remediation.
Legacy report fields remain optional.

Local checkpoint: 517 scanner tests passed (one skipped); the final focused
source/tool/agent pass contains 57 passing checks. Strict mypy across 89 source
files, Ruff and formatting passed. The dashboard passed 97 tests including the
real Python child, TypeScript, ESLint and a production build with isolated test
configuration. Its 85 production HTTP/CLI checks include exact AI evidence
preservation, project isolation and unchanged triage/remediation state. An
isolated Chrome run uploaded a real scanner-generated SARIF with scripted model
responses and verified source excerpts and tool activity at desktop/mobile widths.
The local self-scan checkpoint analyzed 291 files in 181.6 seconds with no analysis
gaps, 708 advisory candidates and zero blocking findings. Documentation checks
passed, retaining the existing color recommendations. Remote CI and merge remain
pending. Live providers, durable dashboard AI jobs, six-role source tools,
calibrated accuracy and independent evaluation remain separate acceptance work.
