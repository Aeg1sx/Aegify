# Aegify quality and release assessment

Assessment updated: 2026-09-25. Proposed release: `v0.3.0-beta.1`.

## Release decision

Aegify is preparing a **team self-hosting beta** for one internal installation
with project roles, CI uploads, durable source/AI finding workers, retained
review evidence and human triage. The scanner CLI, dashboard and CI share the
Python analysis engine. This scoped beta is not a general-availability or
commercial-accuracy certification.

The release remains unpublished until its reviewed commit passes CI and the
signed-tag build publishes the wheel, SBOM, checksums and attestations. Check
[GitHub Releases](https://github.com/Aeg1sx/Aegify/releases) for actual status and
[the beta release contract](docs/releases/v0.3.0-beta.1.md) for installation limits.

## Current implementation evidence

These are recorded checks on the specified revisions, not a claim that every
historical test or benchmark has been rerun on the release candidate.

| Area | Recorded evidence | Boundary |
|---|---|---|
| Scanner and source exploration | [PR #66](https://github.com/Aeg1sx/Aegify/pull/66), head `ea72b193181bc839b58d1ddcd9130fee375a2c6b`: 1,288 Linux tests passed, 84.51% coverage; strict types, lint, rule audit and wheel build passed | Regression coverage does not establish detector or model accuracy |
| Rule surface | PR #66: 311 definitions, 303 executable rules, 986 executable patterns, zero audit errors/warnings | Disabled references and unmodeled semantics are not coverage |
| Dashboard and workers | [PR #65](https://github.com/Aeg1sx/Aegify/pull/65): 171 dashboard tests passed; four Python-dependent checks covered separately; 83 offline Linux worker tests, 154 HTTP/CLI checks and three populated-upgrade checks passed | Scripted providers and owned inputs; no production deployment implied |
| Source-tool agents | PR #66: all six CLI roles use bounded list/search/read requests, source hashes, executor-issued citations, round evidence and partial-result semantics | CLI writes at completion; dashboard finding review is a separate durable path |
| Supply chain | PR #66 required checks, both CodeQL languages, container and documentation checks passed; merged as verified commit `fab40bde745f4e0f1e57c5d2488b3a466949a95f` | Signed release publication is a separate gate |
| Owned core corpus | `core-v1`: five rules, nine positives, paired negatives; TP=9, FP=0, FN=0 | Exact owned corpus only |

The earlier 2026-09-04 assessment (407 scanner tests and 79.78% coverage) and
[alpha completion audit](docs/project/alpha-completion-audit.mdx) are historical
milestones. They are not current release acceptance totals.

## Detection quality

The [retained SQL-expression evaluation](scanner/benchmarks/sql-expressions-v1/README.md)
uses pinned OWASP Benchmark Python source/labels and records two matching runs.
[PR #65](https://github.com/Aeg1sx/Aegify/pull/65) subsequently reproduced the same
case outcomes. This is public diagnostic data, not a private or independent
application-level holdout.

| Scope | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| All candidates, 1,193 scored case/CWE labels | 214 | 99 | 220 | 660 | 68.37% | 49.31% |
| Blocking disposition, same labels | 21 | 28 | 413 | 731 | 42.86% | 4.84% |

All 1,236 Python files were analyzed, but 37 additional CWE-501 labels remain
unscored. Evaluation therefore retains exit `3`; the full quality gate is unmet.
Case/CWE matching does not adjudicate every emitted alert. Public templates are
correlated and labels have not received independent maintainer adjudication.
The five-positive SQL subset's 100% result must not be generalized.

Pinned Juice Shop/DVWA source smoke checks report unsupported scope or other
gaps and have no reviewed accuracy labels. Their accuracy remains unknown.
No existing artifact establishes live AI model quality or calibrated confidence.

## Work required beyond beta

1. **Detection acceptance:** independently review labels and expand held-out
   application data; prioritize false positives, missed flows and unsupported
   CWE coverage using unchanged scoring contracts and paired controls.
2. **Provider acceptance:** run bounded, separately recorded live API/Codex/Claude
   checks, repeated quality evaluations and provider-specific isolation checks.
   Account for unknown usage/cost instead of inferring free calls.
3. **Agent reliability:** add durable per-turn checkpoints and controlled recovery
   to the six-role CLI path; connect dashboard roles only with equivalent source,
   permission and evidence contracts.
4. **Operational acceptance:** measure latency, memory and recovery on fixed
   hardware; record backup/restore outcomes and installation-specific RPO/RTO.
   Project roles within one installation do not establish hosted tenant isolation.

Source/bytecode heap modeling, exception-complete interprocedural analysis,
reflection, dynamic routes and framework configuration remain bounded. See the
[technical architecture](docs/architecture/technical-architecture.mdx).
Static candidates, reachability, runtime observations and impact proof remain
separate; AI output cannot promote their evidence state or authorize execution.

The [commercial-readiness ledger](docs/project/commercial-readiness-plan.md)
retains implementation history and the wider acceptance work.
