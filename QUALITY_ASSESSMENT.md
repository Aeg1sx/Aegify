# Aegify quality and release assessment

Assessment updated 2026-11-27. Published release `v0.3.0-beta.1`.
The new acceptance work below describes the development checkout, not a replacement release.

## Release decision

Aegify has published a **team self-hosting beta** for one internal installation
with project roles, CI uploads, durable source/AI finding workers, retained
review evidence and human triage. The scanner CLI, dashboard and CI share the
Python analysis engine. This scoped beta is not a general-availability or
commercial-accuracy certification.

The signed-tag release includes the wheel, SBOM, checksums and attestations.
[PR #68](https://github.com/Aeg1sx/Aegify/pull/68) corrected the dependency inventory:
the replacement SBOM contains the project and 64 locked dependencies, with 84 edges.
The wheel and signed tag were unchanged. See
[the published release](https://github.com/Aeg1sx/Aegify/releases/tag/v0.3.0-beta.1) and
[the beta release contract](docs/releases/v0.3.0-beta.1.md) for installation limits.

## Current implementation evidence

On the 39 XBOW applications published by ZeroPath, Aegify matched **12 of 33** scorable Python labels and ZeroPath’s archived SARIF matched **9 of 33**. The tools shared seven matches and missed 19 together. Two development gains came from Flask views with an early return. Aegify now also warns on the XBEN-008 repair. XBEN-012 still warns after the repair, with the filter identified in the trace. The checkout and an installed wheel agreed on all labels and eight original/repair pairs. [Cases, controls and replay](scanner/benchmarks/zeropath-python-v1/README.md)

The Jinja update found one of four previously inspected product patch sites. It reports the Jupyter Notebook environment at original line 163 and produces zero warnings at all four repaired locations. The pgAdmin pair and the Flask-Admin URL helper remain missed. The earlier Flask builds found zero of four. [Product patch results](scanner/benchmarks/python-web-xss-patches-v1/README.md)

After freezing the scanner, we selected an additional public Apache Airflow patch using an advisory ordering and inclusion criteria fixed in advance. The scanner missed the original DAG run link formatter and was silent at the repaired site. Each complete module scan also produced five advisories outside the labels. This additional case provides no evidence of a detection gain on previously unseen product code. [Selection, results and replay](scanner/benchmarks/python-web-xss-postfreeze-v1/README.md)

The installed Jinja wheel agreed with the preceding wheel on all 1,230 OWASP Python case records, all 43 XBOW labels and all eight XBOW original/repair pairs. The Jinja checkout passed 2,030 scanner tests with one sandbox loopback test skipped. The preceding dashboard build passed 203 tests with the Python CLI enabled. [Installed wheel and regression records](scanner/benchmarks/python-web-xss-patches-v1/jinja-defaults.json)

In the development dashboard, reviewers can compare a suggested fix with the recorded source excerpt using line numbers, change markers and keyboard-accessible view controls. Source-backed AI reviews require citations covering the reported lines and, for a positive verdict on a recorded flow, its input location. Excerpt-only reviews defer a verdict when its supporting or contrary evidence is absent. The review history shows how many Python files were omitted because the worker could not verify signing-key redaction. The production build passed 837 Chrome assertions and 158 HTTP/CLI access checks on disposable data. [Source review](docs/analysis/ai-sast-operations.mdx#source-navigation-and-references) · [Desktop comparison](docs/assets/aegify-remediation-desktop.png) · [Mobile comparison](docs/assets/aegify-remediation-mobile.png)

The installed candidate matched Wrangler 4.166.0 on all **42 Worker Preview configurations**. The previous wheel missed 17 advisories. The comparison checks primary fields, named environment selection and exact source lines against Wrangler’s configuration reader and Preview request builder. Both candidate processes produced identical results. The local development rule also retained its 29 expected outcomes. These are offline configuration checks. [Comparison and replay](scanner/benchmarks/worker-previews-v1/README.md)

Across 1,230 public Python labels the candidate recorded **452 true positives, 53 false positives, zero false negatives and 725 true negatives**. Two installed processes agreed on all labels. A typed string argument recovered a Flask session flow. Five reader warnings cleared and one labeled HTML negative gained an advisory. Precision reached 89.50%, below the 90% target. Recall reached 100% on this development benchmark. The scanner suite passed 1,873 tests with one loopback test skipped in the sandbox. The wheel matched eight exact reader and session locations, 13 subprocess locations, 13 earlier Python code controls and three saved AI review grades. [Paired cases and controls](scanner/benchmarks/python-reader-flows-v1/README.md) · [Subprocess arguments](scanner/benchmarks/python-process-arguments-v1/README.md) · [Saved review labels](scanner/benchmarks/source-review-v1/README.md)

The dashboard passed 193 unit tests and three database migration tests. The call graph retrieves the selected symbol’s source evidence even with 105 newer observations elsewhere in the same file. [Call graph workspace](docs/analysis/semantic-analysis.mdx#read-a-scans-call-graph)

The local production build passed **801 Chrome checks and 158 HTTP/CLI checks**. The browser imported a cross-file SARIF trace, expanded the helper's recorded line by keyboard and followed a scanned subprocess argument to its source. In workspace settings, applying a provider preset changed the draft URL. Saving a Slack setting preserved the provider draft and its saved protocol. The checks covered 320, 390, 820 and 1440 pixel viewports and dark-theme contrast. A disposable database supplied the examples. [Provider settings](docs/analysis/ai-sast-operations.mdx#configure-the-review-provider) · [Finding review](docs/operations/finding-history.mdx#review-a-finding)

These are recorded checks on the specified revisions, not a claim that every
historical test or benchmark has been rerun on the release candidate.

| Area | Recorded evidence | Boundary |
|---|---|---|
| Scanner and source exploration | [PR #66](https://github.com/Aeg1sx/Aegify/pull/66), head `ea72b193181bc839b58d1ddcd9130fee375a2c6b`: 1,288 Linux tests passed, 84.51% coverage; strict types, lint, rule audit and wheel build passed | Regression coverage does not establish detector or model accuracy |
| Rule surface | PR #66: 311 definitions, 303 executable rules, 986 executable patterns, zero audit errors/warnings | Disabled references and unmodeled semantics are not coverage |
| Dashboard and workers | [PR #65](https://github.com/Aeg1sx/Aegify/pull/65): 171 dashboard tests passed; four Python-dependent checks covered separately; 83 offline Linux worker tests, 154 HTTP/CLI checks and three populated-upgrade checks passed | Scripted providers and owned inputs; no production deployment implied |
| Source-tool agents | PR #66: all six CLI roles use bounded list/search/read requests, source hashes, executor-issued citations, round evidence and partial-result semantics | The published beta writes at completion; development adds explicit checkpoint recovery |
| Supply chain | PR #66 required checks, both CodeQL languages, container and documentation checks passed; merged as verified commit `fab40bde745f4e0f1e57c5d2488b3a466949a95f` | Signed release publication is a separate gate |
| Owned core corpus | `core-v1`: five rules, nine positives, paired negatives; TP=9, FP=0, FN=0 | Exact owned corpus only |
| September development checks | 1,317 local scanner tests passed with the owned loopback test enabled, 84.32% coverage. Six later saved-evidence checks were covered separately and in PR CI | Historical development snapshot |
| September provider and performance evidence | Real Codex CLI completed six roles in twelve calls. The core and Java subset ran in 20 and five sequential processes respectively | One synthetic provider task, small fixed workloads and one host |
| November scanner and workspace | Scanner suite passed 1,457 tests at 84.20% coverage. The sandbox skipped one loopback test, which passed separately. Dashboard passed 177 tests, three migration checks, 155 HTTP/CLI checks and 96 browser checks. The installed wheel classified the expected XML source lines and replayed three saved AI reviews | Local development build on macOS arm64 using owned inputs |
| November specification review and HTTP redirect detection | Two clean installed processes produced identical OWASP Python outcomes. The scanner passed 1,743 tests at 84.92% coverage. The dashboard passed 186 unit tests, three migration checks, 158 HTTP/CLI checks and 440 Chrome checks. Browser coverage includes delayed previews across repositories, a scan outside the recent list, scoped JSON export, dark mode and four viewport widths. [Specification review](docs/operations/api-specifications.mdx#compare-with-a-scan) · [Paired case evidence](scanner/benchmarks/python-redirects-v1/README.md) | One scanner loopback test skipped under the sandbox. The development benchmark scored 87.60% precision and 98.45% recall. Independent application labels and installation-scale provider and recovery evidence remain open. |
| November AI review workspace and LDAP filters | Two installed processes matched on all 1,230 OWASP Python outcomes. The scanner passed 1,715 sandbox tests at 84.81% coverage and one separate loopback redaction test. The wheel also agreed with Wrangler 4.166.0 on the 29 retained configurations. The local dashboard build passed 186 unit tests, three migration checks, 158 HTTP/CLI checks and 389 Chrome checks. Browser checks include source offsets, keyboard selection, mobile setup and dark-theme contrast. [Review screens](docs/analysis/ai-sast-operations.mdx#start-a-review) · [Paired case evidence](scanner/benchmarks/python-ldap-v1/README.md) | Synthetic UI data and a public development benchmark. Precision reached 86.81% against the 90% target. Independent application labels and installation-scale provider and recovery evidence remain open. |
| November directory checks and triage reports | An installed wheel matched three upstream functions before and after their fixes in two runs. All 1,230 public Python outcomes matched the previous scanner. The scanner passed 1,687 sandbox tests at 84.73% coverage plus the separate loopback test. Dashboard checks passed across 186 unit tests, three database upgrades, 158 HTTP/CLI checks and 344 Chrome checks, including the contents of single-page and multi-page PDFs. [Directory comparison](scanner/benchmarks/directory-boundaries-v1/README.md) · [Finding report](docs/operations/finding-history.mdx#read-and-export-a-finding-report) | Six frozen historical source versions from three projects and synthetic UI data. Public Python precision remains 86.38% against the 90% target. Independent application labels and installation-scale provider and recovery evidence remain open. |
| November remote storage and review workspace | Wrangler 4.166.0 and the installed scanner wheel agreed on 29 manifests, including the 10 flagged source lines. The scanner passed 1,668 sandbox tests at 84.69% coverage and the separate loopback test. All 1,230 public Python case outcomes matched the prior build. The dashboard passed 184 unit tests, three migration checks, 155 HTTP/CLI checks and 300 Chrome checks. [Storage reference](scanner/benchmarks/wrangler-storage-v1/README.md) · [Overview](docs/operations/finding-history.mdx#open-the-next-finding) | Static configuration and an owned browser database. Live deployment access, independent application quality and installation-specific recovery remain separate acceptance items. |
| November Python object readers and rule catalog | The scanner passed 1,649 sandbox tests and the separate loopback test. Coverage was 84.62%. An isolated wheel emitted separate pickle and YAML source traces and an advisory for a full loader. The dashboard passed 183 unit tests, three migration checks, 155 production HTTP/CLI checks and 235 Chrome checks. [Rule catalog and detail](docs/analysis/rule-authoring.mdx#browse-detection-rules) | Local production build with synthetic users, repositories and YAML. Browser checks covered administrator access, narrow screens, saved catalog filters, distinct path counts and recovery of an unsaved draft. |
| November Flask responses and inventory | The scanner passed 1,599 sandbox tests at 84.60% coverage and one additional loopback test. A clean wheel reported only the raw Flask body in a four-view fixture. The dashboard passed 182 unit tests, three migration checks, 155 HTTP/CLI checks and 190 Chrome checks. [Endpoint inventory](docs/concepts/attack-surface.mdx#review-endpoint-records) · [Scan history](docs/operations/finding-history.mdx#find-a-scan) | Local production build and synthetic repositories. Browser checks cover scoped counts, narrow screens, keyboard navigation, error recovery and restored filters. Public quality measurements appear below. |
| November filesystem audit and scan record | The scanner passed 1,526 tests in the sandbox and the loopback test separately. The coverage run measured 84.41%. A clean wheel installation distinguished file metadata from content access. The dashboard passed 182 tests, three migration checks, 155 HTTP/CLI checks and 139 Chrome checks. [Desktop and mobile scan record](docs/operations/finding-history.mdx#review-a-scan) | The production build and browser ran locally with synthetic records. Public detection results and independent validation are tracked below. |
| November Cloudflare audit and finding detail | The scanner passed 1,485 tests at 84.30% coverage, with the loopback test passing separately. The dashboard passed 182 tests, three migration checks, 155 HTTP/CLI checks and 121 Chrome checks. A separately installed wheel located both advisory rules in all three supported formats. Its SBOM verified 65 locked dependencies and 85 edges. [Audit scope and screens](docs/analysis/cloudflare-configuration.mdx) | Owned manifests and a local production build. Deployment reachability, credentials and Cloudflare Access policy require independent evidence. |
| November AI source review | Codex CLI 0.166.0 matched three of three owned receipt-projection labels using six calls and three source reads. A separate six-role conformance run completed twelve calls. [Saved inputs, verdicts and replay](scanner/benchmarks/source-review-v1/README.md) | Small authored fixture. Independent application review and configured API-provider measurements are outstanding |
| November queue and recovery | Four SQLite clients contended for 24 jobs in one process. Both runs claimed every job once. The zero-delay run served all jobs on one client. With a 50 ms simulated service delay the clients served 8, 4, 6 and 6 jobs. Both restored archives retained all 25 job records and disabled the fixture account. [Measurements](dashboard/benchmarks/queue-recovery-v1.json) | Controlled queue operations on one host. Production scheduling, load and recovery objectives need installation-specific trials |
| November worker interruption and backup | In each of two independent runs, four processes drained 24 ordinary projects. Three additional processes were terminated after a source claim, before the first AI dispatch and during the second scripted call. Each run published 25 real scanner results with redacted Wrangler findings. The transport recorded 27 sends with zero replays. The restored copy preserved all 50 reviews saved before interruption. [Workload, digests, timings and outcomes](dashboard/benchmarks/worker-pool-recovery-v1.json) | One development host, local SQLite, 41 owned files per scan and 24,000 synthetic historical events. Real provider behavior and installation recovery time remain open. |
| November project directory and job activity | The production build passed 505 Chrome checks, 158 HTTP/CLI checks, 188 dashboard tests and three migration checks. Project search, archival, restore, retained form input, viewer permissions, source event pagination and the AI lease expiry state were exercised. [Project directory](docs/operations/self-hosted-workers.mdx#find-a-project) · [Scan activity](docs/operations/finding-history.mdx#review-a-scan) | Synthetic workspace data and a local Chrome build at four viewport widths. |
| November 22 finding review | 538 Chrome checks, 158 HTTP/CLI checks, 188 dashboard tests and three migration checks passed. A scanner-produced mail finding kept its source line and remediation through SARIF import. The browser checked editor and viewer access, keyboard navigation, assignment persistence and conflicting edits. [Finding review](docs/operations/finding-history.mdx#review-a-finding) | Local production build, owned fixture and 320, 390, 820 and 1440 pixel viewports. |
| November 22 project detail | The production build passed 613 Chrome checks, 158 HTTP/CLI checks, 190 dashboard tests and three migration checks. The project record opens ten revisions at a time and preserves project scope in every severity link. Coverage includes a concurrent repository edit, keyboard retry, reading as a viewer, token issuance and revocation, archived controls, four viewport widths and both themes. [Project record](docs/operations/self-hosted-workers.mdx#review-a-project) | Owned project data. The Git repository directory response was simulated. Project edits, authorization, CI credentials and source job queuing used the running application. |
| November 22 dashboard restore and readmission | Two independent runs stopped the production server and both workers, restored an encrypted snapshot and restarted on the same loopback address. From shutdown, an authorized project read succeeded after 2.568 and 2.613 s. Replacement CI uploads succeeded after 2.832 and 2.881 s. The source worker finished a new rule suite after 5.917 and 5.970 s. Both runs retained the recorded source and triage decision, rejected previous sessions and CI credentials and excluded the post-backup project. [Timings and counts](dashboard/benchmarks/restore-cutover-v1.json) · [Rehearsal](docs/operations/backup-recovery.mdx#rehearse-a-dashboard-cutover) | One arm64 macOS host, local password authentication, two test accounts, one project and a 704 KiB SQLite snapshot. The AI worker registered locally. Installation recovery targets and real provider responses need independent measurements. |

The earlier 2026-09-04 assessment (407 scanner tests and 79.78% coverage) and
[alpha completion audit](docs/project/alpha-completion-audit.mdx) are historical
milestones. They are not current release acceptance totals.

To replay the browser and PDF checks, build the dashboard, install the locked documentation dependencies and provide a local Chrome executable through `AEGIFY_TEST_BROWSER`. From `dashboard/`, run `node --experimental-strip-types scripts/test-ai-review-browser.mjs` with `AEGIFY_TEST_SCANNER_CLI=1`, `AEGIFY_TEST_REPORT_PDF=1` and `AEGIFY_UI_ARTIFACTS` pointing to an existing temporary directory. The PDF assertions use Poppler’s `pdftotext` and `pdftoppm`. The harness creates a disposable database and synthetic records. [Browser harness](dashboard/scripts/test-ai-review-browser.mjs)

The same installed scanner reproduced all 29 stored Wrangler configuration outcomes and agreed with all three labels in the saved AI review replay. The latter uses recorded provider responses. [Wrangler configuration comparison](scanner/benchmarks/wrangler-storage-v1/README.md) · [Saved review grading](scanner/benchmarks/source-review-v1/README.md)

## Detection quality

On fixed source ranges in seven production modules from five public projects, the TLS detector found both development positives and three of six initially held-apart positives. After inspecting the Airflow provider miss, the development build found four of those six historical sites and cleared all six corrected locations. DIRAC and Weblate remain missed. An additional advisory identifies a retained CKAN opt-out outside the labeled default branch of its mail configuration. Independent reviewers have yet to adjudicate the labels. [Application cases, paired results and replay](scanner/benchmarks/transport-verification-v1/README.md#follow-up-on-airflows-synchronous-mail-client)

The same installed wheel retained all 1,230 OWASP case outcomes in each of three scoring channels, matched Wrangler 4.166.0 on 29 configuration fixtures, and reproduced all three saved AI review grades. The scanner suite passed 1,771 tests. The local sandbox skipped one loopback proxy test. [OWASP comparison](scanner/benchmarks/transport-verification-v1/owasp-comparison.json) · [Wrangler fixture](scanner/benchmarks/wrangler-storage-v1/README.md) · [Saved AI reviews](scanner/benchmarks/source-review-v1/README.md)

The redirect update scored **87.60% precision and 98.45% recall** across
1,230 labeled OWASP Python cases (445 TP, 63 FP, 7 FN, 715 TN). The CWE-601
subset recovered four positives and cleared four false positives. All other
case outcomes stayed the same in each channel. The remaining redirect false
positive uses a dynamically selected method with an unresolved return type.
[Redirect evaluation and installed-wheel replay](scanner/benchmarks/python-redirects-v1/README.md)

The directory search model scored **86.81% precision and 97.57% recall**
across 1,230 labeled OWASP Python cases (441 TP, 67 FP, 11 FN, 711 TN).
All 16 CWE-90 positives gained a filter finding. All 13 LDAP negatives stayed
clear. Two fresh installed processes produced identical outcomes. Application
holdouts and the 90% precision target remain open.
[Directory filter evaluation and replay](scanner/benchmarks/python-ldap-v1/README.md)

The Python object-reader update scored **86.38% precision and 94.03% recall**
across 1,230 OWASP labels (425 TP, 67 FP, 27 FN, 711 TN). It cleared seven
CWE-502 false positives, retained all 18 positives, and added blocking evidence
on nine of those positives. The five remaining CWE-502 false positives are
advisory. Both the 90% precision target and application-level evaluation remain
open. [Object-reader evaluation and replay](scanner/benchmarks/python-decoders-v1/README.md)


Two fresh processes scored all 1,230 public OWASP Python labels with identical
case outcomes. All-candidate precision reached **85.17%** and recall reached
**94.03%** (425 TP, 74 FP, 27 FN, 704 TN). The previous results were 84.07%
for both measures. The Flask response rule found 31 of 31 XSS positives and
flagged zero of 58 XSS negatives. Its findings are advisory. Across all CWEs
45 previously missed positives were detected. Two previously clean negatives
were flagged, one path and one redirect. The blocking channel recorded 153 TP,
46 FP, 299 FN and 732 TN. The precision target of 90% and independent application
review remain open. [Flask evaluation](scanner/benchmarks/flask-responses-v1/README.md) ·
[Previous filesystem evaluation](scanner/benchmarks/python-paths-v1/README.md)

## September detection baseline

The [September acceptance record](scanner/benchmarks/beta-quality-v1/README.md) replays
main `d4bd04e8779e767f0babce6bcdd5b4a6d3ee5922` and compares two matching runs of
the Python syntax fix against unchanged OWASP source, labels and scoring.
Literal template text no longer creates taint reads; annotated and augmented
assignments preserve real flows. This is public diagnostic data, not a private
or independently adjudicated application-level holdout.

| Scope | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Baseline all candidates, 1,193 scored labels | 214 | 99 | 220 | 660 | 68.37% | 49.31% |
| Development all candidates, same labels | 215 | 94 | 219 | 665 | 69.58% | 49.54% |
| Development blocking disposition, same labels | 24 | 20 | 410 | 739 | 54.55% | 5.53% |

Eight FP→TN and one FN→TP transitions accompany **three TN→FP regressions**:
`BenchmarkTest00007`, `BenchmarkTest00073`, and `BenchmarkTest00520`.
Restoring augmented-assignment flow exposes unsupported guard semantics.
The strict no-case-regressions comparison fails (exit `1`); no labels, suppressions
or thresholds were changed to turn it green. This change is not release acceptance.

All 1,236 Python files were analyzed, but 37 additional CWE-501 labels remain
unscored. Evaluation therefore retains exit `3`; the full quality gate is unmet.
Case/CWE matching does not adjudicate every emitted alert. Public templates are
correlated and labels have not received independent maintainer adjudication.
The five-positive SQL subset's 100% result must not be generalized.

Pinned Juice Shop/DVWA source smoke checks report unsupported scope or other
gaps and have no reviewed accuracy labels. Their accuracy remains unknown.
A separately authored OWASP Java corpus adds 2,740 unchanged upstream labels,
with a pinned archive and per-file acquisition manifest. It is public synthetic
data; independent label adjudication and private application holdouts remain open.
The live Codex CLI check passes the six-role source protocol on a three-line
owned fixture. It does not establish live AI model quality or calibrated confidence.

## Work required beyond beta

1. **Detection acceptance:** independently review labels and expand held-out
   application data; prioritize false positives, missed flows and unsupported
   CWE coverage using unchanged scoring contracts and paired controls.
2. **Provider acceptance:** Codex conformance is recorded; live API and Claude
   checks still need credentials/installations. Repeat on labeled review tasks
   and verify provider-specific isolation; unknown usage/cost remains unknown.
3. **Agent reliability:** development now checkpoints provider calls and replays
   saved responses without redispatch. Uncertain calls stop for operator review.
   Dashboard role parity and distributed recovery remain separate work.
4. **Operational acceptance.** The development measurements cover fresh scanner
   processes, four worker processes, abrupt shutdown and concurrent writes
   during backup. The local restore drill reaches a fresh operator login, CI
   delivery and source worker result. Installation traffic, off-host storage,
   real identity and AI providers still need deployment-specific measurements.
   Project roles within one installation do not establish hosted tenant isolation.

Source/bytecode heap modeling, exception-complete interprocedural analysis,
reflection, dynamic routes and framework configuration remain bounded. See the
[technical architecture](docs/architecture/technical-architecture.mdx).
Static candidates, reachability, runtime observations and impact proof remain
separate; AI output cannot promote their evidence state or authorize execution.

The [commercial-readiness ledger](docs/project/commercial-readiness-plan.md)
retains implementation history and the wider acceptance work.
See [the acceptance guide](docs/project/beta-quality-acceptance.mdx) for commands,
recorded measurements, checkpoint behavior and remaining gates.
