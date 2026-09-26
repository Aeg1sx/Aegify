# Aegify quality and release assessment

Assessment updated: 2026-09-26. Published release: `v0.3.0-beta.1`.
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
| Current development checks | 1,317 local scanner tests passed with the owned loopback test enabled, 84.32% coverage; strict types, lint, rule audit and wheel build passed. Six later saved-evidence checks are covered separately and in PR CI | The latest exact-head CI record remains authoritative; unit tests do not override the three measured case regressions |
| Current provider/performance evidence | Real Codex CLI: six roles / twelve calls; core: 20 sequential processes; Java subset: five sequential processes | One synthetic provider task, small fixed workloads and one host; not calibrated AI quality or a service SLO |

The earlier 2026-09-04 assessment (407 scanner tests and 79.78% coverage) and
[alpha completion audit](docs/project/alpha-completion-audit.mdx) are historical
milestones. They are not current release acceptance totals.

## Detection quality

The [new acceptance record](scanner/benchmarks/beta-quality-v1/README.md) replays
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
4. **Operational acceptance:** fresh-process latency/RSS measurement and CI
   evidence are implemented. Extend the bounded scanner measurements to queues,
   concurrent workers, database load, backups and installation-specific RPO/RTO.
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
