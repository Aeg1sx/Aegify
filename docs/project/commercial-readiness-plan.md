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
| Repository context | Collision-safe multi-repository and monorepo identity, dependencies, snapshots and incremental invalidation | Cross-repository fixtures; incremental/full result equivalence | In progress |
| Rule authoring | Guided templates, schema diagnostics, source/sink/propagation explanations, preview and regression cases | Author a rule, preview matches, export and run it in CI | Pending |
| AI review | Bounded source browsing and evidence tools for threat modeling and supplied-finding review, abstention, triage and remediation advice | Tool-contract tests, source-bound citations, model comparison and repeated-run evaluations | In progress |
| Agent operations | Durable jobs, logs, tool spans, evidence events, cancellation, retry, budgets and cost accounting | Worker interruption/recovery tests and dashboard observation | In progress |
| Provider support | Claude Code and Codex adapters with explicit models, bounded read-only tools and reproducible traces | Local contract tests plus separately recorded live-provider checks | Pending |
| Product experience | Clear analysis scope, uncertainty, repository navigation, data flow/graph views and triage workflow | Browser checks of the complete user flow and accessibility | In progress |
| Open-source evaluation | Pinned Juice Shop, DVWA and other relevant source corpora, with support gaps reported honestly | Static-only runs, scope inventory, reviewed labels and documented results | In progress |
| Efficiency | Fixed-hardware latency/memory/cost baselines, dependency-aware incremental work and cache invalidation | p50/p95 and peak-memory reports; unchanged-result comparison | In progress |
| Reproducibility | Engine/parser/rules/modelpack/config/source/provider manifests and replayable evidence | Clean-environment replay and artifact-digest checks | In progress |
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
passed, retaining the existing color recommendations. All required remote CI,
container checks, CodeQL and self-scan passed on head
`03ec95df4b1f8bd1a4ab31295b38be413ddfec4f`. PR #46 merged at
`4efce337d17e8c54bdc6fa9c5c1531fd13f2dad1` with a verified GitHub signature.
Live providers, durable dashboard AI jobs, six-role source tools,
calibrated accuracy and independent evaluation remain separate acceptance work.

## Team backup and recovery checkpoint: 2026-09-24

Added an operator-only encrypted SQLite backup, verification and restore CLI to
the worker image. Live backups use a consistent `VACUUM INTO` snapshot, retain
the snapshot interval, and authenticate the metadata and database with a separate
archive key. A stored ciphertext, when present, checks the original installation
key. Header size, database size, schema, counts, integrity and foreign keys are
validated before publication. Outputs are private, created atomically without
overwriting existing files, and interrupted restore transactions remain unpublished.

Restore creates a candidate database, disables all existing accounts, rotates a
new session epoch, revokes project CI tokens, blocks legacy environment upload
credentials, clears authentication tokens and cancels unfinished scans/AI jobs.
Old approvals and worker registrations are invalidated. Historical findings,
completed scans, triage and audit records remain. Operators reactivate admitted
accounts individually; local accounts require a different password. The session
epoch migration keeps existing sessions valid during a normal software upgrade
but prevents pre-recovery cookies from becoming valid when counters roll back.

Local checks: 100 dashboard tests passed, including real Python worker execution,
fresh and existing-user migrations, WAL snapshot isolation, encrypted archive
contents, wrong keys, damaged/truncated archives, unchanged source state, access
revocation, local-password login, concurrent publication and a late transaction
failure. Three final focused recovery tests passed after the last assertion
change. The production build, TypeScript, ESLint and 87 production HTTP/CLI checks
passed; the HTTP checks reject an old cookie after epoch rotation and admit a new
cookie. Documentation validation, links and accessibility checks passed with the
existing color recommendations. All required remote checks, CodeQL and self-scan
passed on `fe44b5796fe8d80a5612402798b5833a83815ce4`. The read-only non-root Linux
worker passed 15 offline contract tests, including all three recovery tests;
container startup applied all 18 migrations and retained data across restart.
PR #47 merged at `1e7c53120028b3b1aafbe552e31b418e0282392a` with a verified
GitHub signature.

The first recovery self-scan reported four blocking SQL candidates at two bound
operator queries. Their source paths depended on `node:path.resolve` incorrectly
binding to an unrelated project function, including a second same-name fallback
inside the taint solver. Both resolvers now respect declared imports and the Node
namespace. Forty-two focused graph/taint checks pass, covering named/aliased/
namespace imports, missing modules, unchanged local edges, conservative taint
through an unknown library call, cross-repository propagation and a 1,000-call
resolution bound. No query or rule was suppressed to pass the scan.
The final full scanner suite passed 525 tests with one skip; strict mypy passed
across 90 source files, and Ruff/format checks passed across 146 files.
The final local self-scan completed 296 files in 161.7 seconds with no reported
analysis gaps, 746 advisory candidates and zero blocking findings. The four
incorrect blocking paths are absent; individual advisory triage remains open.

The documented drill includes candidate review, administrator activation, explicit
database promotion, integration review, new project CI credentials and measured
recovery time. No live production installation was backed up or switched. Scheduled
backups, off-host transport, configurable retention, external credential rotation
and installation-specific RPO/RTO acceptance remain open.

## OAuth scope rule precision: 2026-09-24

The alert snapshot captured before PR #47 merged contains 714 open alerts
(709 Aegify and five Scorecard), including 68 `AEG-OAUTH-004` alerts. Counts are a
dated inventory, not individual vulnerability verdicts. Inspecting matched source
identified file-wide joins between generic `scope` names and unrelated privilege
keywords, plus `get_token` substring matches on `get_token_usage()`.

The rule now binds selected OAuth authorization/provider calls to their own scope
arguments, matches explicit OAuth configuration names and bounded literal values,
and requires exact token-exchange methods with OAuth context. Existing callback
checks remain function-scoped. Findings retain advisory/candidate status and ask
for application-policy and library/provider review. Scope differences alone are
not described as a confirmed vulnerability; a provider may grant fewer privileges.

Thirty bundled-rule precision checks pass, including five explicit string/list
scope positives, six nearby negative cases, validated callbacks and a 1,000-item
metadata bound. A paired evaluation over the same 296-file self-scan cohort changed
69 raw OAuth matches to zero: 67 file-wide assignment matches and two callee
substring matches. `scanner/benchmarks/rule-regressions/oauth-scope-v1.json`
records the baseline commit, old/new rule hashes, affected file hashes and lines.
These regression fixtures and candidate counts do not establish product precision,
recall, runtime exploitability, or independently reviewed real-world labels.
The full scanner suite passes 537 tests with one skip. Ruff and formatting pass;
the changed rule file passes strict audit with four executable rules, 15 executable
patterns and no errors or warnings. The full self-scan completes 296 files in
150.5 seconds with 677 advisory candidates, zero blocking findings and no reported
analysis gaps. The dashboard's YAML validation accepts the four definitions with
no diagnostics; documentation validation, links and accessibility checks pass
with the existing color recommendations. Remote exact-head checks and post-merge
GitHub alert state remain separate gates.

All required CI, CodeQL, Linux container checks and self-scan passed on
`116a761d589975d3da6191ff8a4a65888ee5932c`. PR #48 merged at
`8caa07e9160455663be84e135aea18615ee4a022` with a verified GitHub signature.
Main analysis `1828761753` on that merge completed at 2026-09-23T22:02:33Z
with 677 Aegify candidates, down from 746 on the preceding merge. The refreshed
GitHub snapshot contains 682 open alerts (677 Aegify, five Scorecard) and zero
`AEG-OAUTH-004` alerts. No alert-dismissal API was called. Remaining alerts still
require disposition; an empty OAuth result does not establish OAuth security.

## External case evaluation checkpoint: 2026-09-24

Added `aegify benchmark-owasp` for the official Python case-label CSV. It runs the
common static engine with an explicit Python inventory, serial parsing, bundled
rules, low severity, uncapped outputs and 50,000 taint contexts. It ignores corpus
and environment scanner configuration, uses memory storage and does not install
or execute corpus code or call a model. Corpus/label/implementation changes during
analysis invalidate the result. All corpus files, including OpenAPI and other
auxiliary inputs, contribute to the source digest.

The evaluator matches an exact case path and declared CWE at most once per
case/channel. It separates all-candidate, advisory and blocking metrics, preserves
undefined ratios as null, and reports per-CWE/per-rule counts, balanced accuracy,
MCC and descriptive Wilson intervals. Missing files and absent CWE rules remain
unscored; a global scan gap makes all cases unscored. Findings for other CWEs or
outside labeled cases remain separate observations. This case-level contract
does not measure the precision of every emitted alert or prove runtime impact.

Pinned OWASP Benchmark Python commit
`f1291485808b66e20ddb6b01b10dc71b3df8c8ba` supplies 1,230 public synthetic cases
(452 positive, 778 negative). All 1,236 Python files were analyzed without scan
gaps. Thirty-seven CWE-501 cases remain unscored because no executed rule declares
that CWE. Within the 1,193 scored cases, all-candidate results are TP=209, FP=114,
FN=225, TN=645: precision 64.71%, recall 48.16%, F1 55.22%, accuracy 71.58%.
Recall over all 452 positive labels is 46.24%. Blocking results have TP=21, FP=28,
FN=413, TN=731: precision 42.86%, recall 4.84%. Exact CWE matching applies no
implicit parent/child aliases. These results do not meet a 90% quality gate.

The scan emitted 10,851 findings. Of these, 10,332 concern a different CWE from
the case's intended label and 14 are outside labeled case files. They require
separate review and are not automatically counted as false positives. The 505
matching observations collapse to 323 detected cases. Source-model gaps, typed
sanitizers, branch handling and option-sensitive cookie/XML rules need work.

`scanner/benchmarks/owasp-python-v01` retains aggregate metrics, every case outcome,
upstream/archive/label hashes, scanner code/modelpack/rule/parser/package/config
provenance and two fresh-process runs. Both have identical provenance, metrics
and outcome digest `174f01620ccb79b7fe4c9ea613168552bf186caccfff8630724a8372c0442229`.
Observed scan times are 225.21 and 224.40 seconds, with process RSS peaks of
369,082,368 and 367,722,496 bytes. Concurrent developer-machine work is recorded;
these are not fixed-hardware p50/p95 guarantees. Both evaluations correctly exit
3 because 37 cases remain unscored. Public labels are not independently adjudicated
application evidence or a held-out AI benchmark.

The preflight full scanner suite passed 559 tests with one skip. After clarifying
the serial runner interface and adding retained-artifact integrity checks, all
23 final focused evaluation tests pass. Ruff/format checks pass across 149 files,
strict mypy passes across 92 source files, and documentation validation, links
and accessibility pass with existing color recommendations. The final self-scan
analyzed 298 files in 153.7 seconds with no reported gaps, 678 advisory candidates
and zero blocking findings. Exact-head remote CI subsequently passed, including
561 scanner tests with 81.81% coverage, dashboard, CodeQL, self-scan, supply-chain,
documentation and container checks. PR #49 merged through the recorded maintainer
procedure on 2026-09-23 at 22:36:19 UTC as verified signed commit
`4fffd1c1fa5401577b1a01e8964cb88d4decbe08`.

A separate owned identity check found that the same repository ID, module path
and evidence text receive different finding fingerprints when only the checkout
root changes. Correcting this CI/worker triage continuity issue, including legacy
identity compatibility and multi-repository separation, is follow-up work.

## Finding identity continuity: 2026-09-24

The owned check found two separate defects: Aegify's fingerprint included the
physical checkout path, and the dashboard accepted opaque producer hashes without
qualifying them by rule or repository. Absence reconciliation also depended on
physical paths. These could lose existing triage or join unrelated observations.

The v2 contract uses the exact rule, repository ID, relative module and full
retained snippet/message, with shared Python/TypeScript golden vectors. Source
case, numbers and internal whitespace are preserved; line numbers and known
checkout roots are excluded. The old producer fingerprint remains in SARIF for
compatibility. The importer recomputes Aegify source identities and qualifies
other supported producer hints by namespace.

A new additive migration retains identity IDs and triage history while backfilling
only unambiguous logical scopes. Bounded, one-to-one legacy upgrades occur inside
the artifact publication transaction and are audited. Conflicting or unavailable
legacy evidence remains retained; incoming identities start open, with partial
scan health and a review diagnostic. Versioned, validated analyzed-source pairs
allow default-branch absence reconciliation across checkout changes without
affecting sibling repositories, excluded files or disabled rules.

The focused local suite passes 28 tests, including a real Python engine scan in
two fresh checkout roots, imported SARIF fingerprint agreement, an actual
pre-migration SQLite database, conflicting legacy decisions, cross-project and
repository/rule separation, injected late rollback, malformed source coverage,
20,000 inventory entries and a 5,001-identity migration budget. The whole scanner suite passes 563 tests with one local platform skip; all 115
dashboard tests pass, including the real Python subprocess checks. Ruff and
format checks pass across 151 files, strict mypy across 93 source files, and
TypeScript and ESLint pass. A production build with ephemeral test configuration
and 95 local production HTTP/CLI checks pass, including human triage across
checkout changes and reopening after a complete absence. Documentation syntax,
links and accessibility pass with the existing color recommendations. The initial
local self-scan analyzed 300 files in 160.6 seconds, with no coverage gaps, 686
advisory candidates and zero blocking findings. Exact-head remote CI remains a
separate gate.

At that checkpoint, remaining workflow scope included assignment/due-date/tag/ticket
continuity (then stored per observation), an operator conflict-review interface,
incremental/full equivalence, and broader application-level accuracy evaluation.
This phase does not establish commercial detection quality.

All required CI, both CodeQL languages, the Aegify self-scan and container checks
passed on head `6fcdbae0d0898e0037a36d97df2798f95a51926a`. Linux CI passed all
564 scanner tests with reported coverage rounded to 82%, and 25 offline worker,
migration and recovery checks. Fresh installation applied 19 migrations. PR #50
merged at 2026-09-23T23:36:31Z as signed, verified commit
`3ad3184d2809c2c2e1f2c06c6277c47464b319ba`. Its main-branch Aegify analysis
`1829182657` completed at 2026-09-23T23:41:33Z with 686 candidates and no analysis
error. Both CodeQL analyses on that commit have zero results. No live production
installation was upgraded. The subsequent open-alert snapshot contains 691 alerts:
686 Aegify candidates and five Scorecard alerts. No dismissals were performed.

The merged #49 baseline has completed main-branch Aegify analysis
`1828934261` (2026-09-23 22:39:26 UTC). Its refreshed snapshot contains 683 open
code-scanning alerts: 678 Aegify candidates and five Scorecard alerts. No alert
was dismissed as part of the evaluation or identity work. Alert counts are not
a substitute for per-finding security review.

## Team finding workflow: 2026-09-24

An owned production HTTP regression first showed that an assigned team disappeared
when the same finding was imported from a new CI checkout. The identity now owns
assignment, due date, priority, tags and ticket metadata. Imports inherit that
workflow, updates affect current observations atomically, and historical rows
retain their saved values. Optimistic workflow versions reject stale changes;
permissions, account admission and archive state are rechecked in the transaction.

An additive migration copies only a unique, bounded latest assignment with known
logical scope. Other legacy assignments remain retained and require explicit
review. The dashboard displays current controls on historical findings, disables
edits for read-only users, preserves conflicting drafts and offers a visible
reload action. The API now requires `expectedVersion`; existing clients must
GET the current workflow version first. Expired triage reopens once and clears
the active expiry while retaining the event history.

Completed synthetic ticket receipts propagate to the current identity and future
scans; conflicting receipts retain an audit record. No actual Jira ticket was
created. A persistent delivery reservation/outbox and uncertain-result recovery
are still needed: concurrent empty preflights or a timeout/database outage can
produce an unlinked remote issue. No exactly-once integration claim is made.

Final local checks passed all 124 dashboard tests, including actual Python subprocess
contracts, and 104 production HTTP/CLI checks. An isolated Chrome check exercised
two users changing one finding, draft preservation after `409`, reload and save,
historical/current ownership, ticket display and viewer controls. No browser page
errors occurred. A further simultaneous-writer SQLite check passed, allowing one
commit and rejecting the stale competitor. Fresh-schema and populated legacy
migration checks preserve historical rows; injected audit failure rolls the
workflow update back. A fresh Prisma deployment applies all 20 migrations.
TypeScript, ESLint and the final production build pass. The final browser run also
preserves an unsaved triage draft when assignment is saved and rejects that stale
triage save until reload. Documentation validation, links and accessibility pass
with existing color recommendations. A preflight self-scan analyzed 302 files in
159.7 seconds with no reported gaps, 693 advisory candidates and zero blocking
findings. Final exact-head CI and merge remain separate gates.

All required checks, CodeQL in both languages, self-scan and container checks
passed on final head `16b50dfea661125572a0a05cf310fa350909dc11`. Linux CI passed
564 scanner tests and 34 offline worker, recovery and workflow checks; the
container applied all 20 migrations. Equal Jira keys from different installations
also retain separate linkage. PR #51 merged on 2026-09-24T00:31:08Z as verified
signed commit `456255ea76fe5e87714969a2a20302556a25679d`. No production installation
or external Jira/provider action was performed. Main analysis `1829373077`
completed at 2026-09-24T00:36:04Z with 693 Aegify candidates and no reported error;
both CodeQL analyses on the merge have zero results.
The refreshed open-alert snapshot contains 698 alerts: 693 Aegify candidates and
five Scorecard alerts. No alert was manually dismissed.

This phase improves team workflow reliability. It does not change the measured
OWASP precision/recall, establish live-provider AI quality, or complete the wider
self-hosting release contract.

## Hash algorithm rule precision: 2026-09-24

Source review of the workflow self-scan found SHA-256 calls labeled as MD5. An
owned source-only regression confirmed this for both SHA-256 and SHA-512. The MD5
rule's factory argument expression accepted every argument, and partial callee
matching also admitted metadata and unrelated names. SHA-1 selection had related
callee/argument attribution gaps.

The two rules now distinguish exact named constructors from factories whose
first argument selects the literal algorithm. Messages request security-use and
resolved-API review; findings remain advisory candidates. Explicit call fixtures
cover eight parser languages, safe factory algorithms, names in other arguments,
metadata, dynamic values, zero-argument constructors and nearby strong hashes.
Computed choices, wrapper/alias resolution and distinguishing non-security use
remain outside this change's coverage.

A paired comparison over the same 302 source files at workflow head
`16b50dfea661125572a0a05cf310fa350909dc11` removed 16 MD5 candidates at SHA-256
calls and one SHA-1 metadata candidate, with no added candidate in that cohort.
These are reviewed regressions in this repository, not a universal accuracy
estimate. The first full OWASP Python rerun preserves CWE-328 TP=71, FP=0, FN=0,
TN=80 and the overall baseline metrics. Per-rule attribution changes, so the
outcome digest differs from the frozen original baseline. A separate report
retains the new provenance; the original evaluation artifacts remain unchanged.

The full local scanner preflight passed 594 tests with one platform skip.
Ruff and formatting pass across 152 files; the changed rule file passes strict
audit with ten executable rules, 17 executable patterns and no warnings/errors.
The final focused suite passes 32 tests, including the observed metadata decoy
and complete-analysis assertions for every source fixture. A replay script and
301 tracked-file digests preserve the paired comparison; the initial 302-file
cohort additionally contained generated Next.js declarations with no hash match.

Two independent OWASP processes have identical provenance, case outcomes and
all metrics, with outcome digest
`45aff2e6f1253bf6252febbdcc95ab18249b0a90f35088d760f8bf958d2a0ec9`.
`scanner/benchmarks/hash-selection-v1` retains the new metrics, all case outcomes,
source/rule provenance and replay commands. Observed scan times are 206.93 and
202.00 seconds; process RSS peaks are 368,787,456 and 367,460,352 bytes. Both runs
correctly exit 3 for the 37 unscored CWE-501 cases; no quality-gate pass is claimed.

The preflight worktree self-scan analyzed 301 files in 144.9 seconds with no
reported gaps, 676 advisory candidates and zero blocking findings. Its generated
file inventory differs from the prior development checkout; the pinned paired
comparison is the evidence for the rule-specific reduction. Documentation checks
pass with existing color recommendations. Exact-head remote CI remains the merge
gate, including the replay script added after this preflight scan.
The added replay script separately passes its pinned comparison and an owned
single-file self-scan with no findings or analysis gaps; Ruff/format checks pass
across 153 source, test and replay files.

All required checks, both CodeQL analyses, self-scan and container checks passed
on head `53382df85587d9e422073e8a48a4164b6f5ad198`. Linux CI passed 596 scanner
tests with reported coverage rounded to 82%; the dashboard passed 124 tests and
the offline container passed 34 checks with all 20 migrations. PR #52 merged at
2026-09-24T00:51:44Z as verified signed commit
`32659293bff58195cc4cea2d8bb5dcee90480da1`. Main Aegify analysis `1829441217`
completed at 2026-09-24T00:57:17Z with 676 candidates and no error; both CodeQL
analyses on that merge have zero results. The fresh open-alert snapshot has 681
alerts: 676 Aegify candidates and five Scorecard alerts. No manual dismissal was
performed. The comparison also replays from a fresh detached checkout of the
pinned source, with the same 301 files, 17 removed candidates and no additions.

## Scanner agent provider contracts: 2026-09-24, in progress

Eight offline regressions first reproduced incomplete OpenAI strict-schema fields,
unfinished/refused Responses envelopes accepted as valid narratives, and an
oversized Codex output file accepted after truncation. The adapters now require
all narrative fields, validate provider completion/refusal states, reject ambiguous
JSON and retain bounded failure codes. Finished runs with incomplete stages are
reported as partial while preserving deterministic facts.
The CLI persists its artifact and returns exit 3 for partial/awaiting-approval
runs, allowing CI to distinguish them from a completed review (exit 0).

The CLI transport now sends input while draining bounded stdout/stderr, enforces
a deadline and terminates its POSIX process group even after successful parent
exit. Codex message files are monitored and read as bounded regular UTF-8 files.
The first expanded local check passed 83 focused tests, including real owned
subprocesses and descendants. The initial process-inspection test hit the local
sandbox's `ps` restriction; it now checks only its owned child PID directly and
recognizes Linux zombie state. No restriction was relaxed.

Official OpenAI structured-output/Codex configuration and Claude Code result
contracts were checked. Installed Codex 0.155.1 help accepts the current flags;
no live CLI/model invocation, credential check, usage-cost verification or real
provider-quality evaluation was performed. Inherited CLI configuration/hooks,
detached descendants, external isolation, provider-neutral usage/cost receipts
and durable AI jobs remain open work. Exact-head CI remains a separate gate.

The full scanner preflight passed 657 tests with one platform skip; subsequent
focused checks pass 92 tests covering CI exit codes and premature stdin closure. Legacy artifact
digest compatibility is checked against an independently computed pre-change
digest. Ruff, formatting and strict types pass; documentation validation, links
and accessibility pass with existing color recommendations. The sandboxed
documentation command initially failed during its network availability probe;
the approved normal-network retry of the same command passed.

The preflight self-scan analyzed 301 files in 203.4 seconds, with 677 advisory
candidates, no blocking finding and successful analysis. Its one added candidate
is `AEG-HDR-003` at the `_NoRedirects` class declaration: source review confirms
this hook rejects redirects rather than writing an HTTP response/header. It is a
retained heuristic false positive for a separate rule fix; no alert suppression
or rule weakening is included here. Exact-head CI remains the merge gate.
