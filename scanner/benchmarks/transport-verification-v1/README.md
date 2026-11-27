# Certificate verification in Python applications

Seven maintained Python modules from five projects supplied eight pairs of source locations for CWE-295. The evaluator scans the entire module at the parent and fix commits. Each pair covers one client configuration or policy. The manifest fixes the source hashes, line ranges, split and maintainer reference. [Case manifest](cases.json)

| Sites by split | Build | Detected before fix | Missed before fix | Flagged after fix | Clear after fix |
|---|---|---:|---:|---:|---:|
| Development · CKAN and SageMaker | Previous | 0 | 2 | 0 | 2 |
| Development · CKAN and SageMaker | Candidate | 2 | 0 | 0 | 2 |
| Evaluation · Airflow, DIRAC and Weblate | Previous | 1 | 5 | 0 | 6 |
| Evaluation · Airflow, DIRAC and Weblate | Candidate | 3 | 3 | 0 | 6 |

All 14 module versions completed in both builds. Two candidate processes produced byte-identical scored reports. The previous and candidate wheels share the development version string. Their SHA-256 digests distinguish them. [Previous results](previous.json) · [Candidate results](result.json) · [Wheel and replay identities](replay.json)

On a hash-matched export of the public OWASP Python corpus, all 1,230 cases retained their previous all-candidate, advisory and blocking outcomes. All-candidate precision was 87.60% and recall was 98.45%. This regression run has its own matching rules and ground truth. [OWASP paired comparison](owasp-comparison.json) · [OWASP baseline and replay commands](../python-redirects-v1/README.md)

## What the evaluation covers

The cohort was selected from public, reviewed Python advisories on certificate verification. The ranges and split were recorded before scoring. The third-party maintainers documented the fixes. The Aegify evaluation selected the cases and mapped the source locations. The small, purposive sample and the related Airflow modules limit conclusions about other projects.

| Held-apart site | Candidate result | Maintainer change |
|---|---|---|
| Airflow Databricks, synchronous and asynchronous HTTP | Detected both explicit client overrides. Both corrected locations were clear. | [Airflow Databricks change](https://github.com/apache/airflow/pull/63704) |
| Airflow core SMTP | Detected the implicit standard-library context. The corrected call was clear. | [Airflow mail change](https://github.com/apache/airflow/pull/65346) |
| Airflow SMTP provider | Missed the synchronous call. The same instance field can hold standard-library and asynchronous clients. The corrected call was clear. | [Airflow mail change](https://github.com/apache/airflow/pull/65346) |
| DIRAC generated client | Missed the policy in Python embedded in a string. The corrected location was clear. | [DIRAC advisory](https://github.com/DIRACGrid/DIRAC/security/advisories/GHSA-vg99-gr89-qhw9) |
| Weblate client | Missed a host-selection policy that controls certificate verification. The corrected location was clear. | [Weblate advisory](https://github.com/WeblateOrg/wlc/security/advisories/GHSA-2mmv-7rrp-g8xh) |

One additional candidate was recorded outside the labels. CKAN retains a separate operator-controlled opt-out on line 146 of its fixed module. Its labeled verified branch on line 144 was clear. SageMaker removed a process-wide HTTPS context override from the labeled module initialization. [CKAN advisory](https://github.com/ckan/ckan/security/advisories/GHSA-mpfm-fpgx-647q) · [SageMaker advisory](https://github.com/aws/sagemaker-python-sdk/security/advisories/GHSA-62rc-f4v9-h543)

## Follow-up on Airflow's synchronous mail client

The SMTP provider stores its synchronous and asynchronous clients in the same field. In the synchronous method, a successful assignment inside a Python `try` precedes the STARTTLS call in its `else` suite. Aegify now resolves the client on that path. The historical module produced one advisory static candidate at line 129. The corrected call at line 129 supplied the application's context and was clear. Controls cover conditional assignment, exception handlers and cleanup paths. [Airflow change](https://github.com/apache/airflow/pull/65346) · [Python try statement](https://docs.python.org/3/reference/compound_stmts.html#the-try-statement)

The earlier six-site evaluation supplied this development case. With the original hashes and labels, detection rose from three to four of six historical sites. All six corresponding corrected sites stayed clear. The two original development pairs also retained their outcomes. Weblate's host-selection policy and DIRAC's generated client remain missed. [Follow-up result](try-else.json)

## Weblate host selection

A separate partial-comparison advisory, `AEG-HOST-001` (CWE-187), now identifies the parsed authority prefix check on line 377 of the historical Weblate client. Scanning the corrected module produced zero alerts for that rule. The original CWE-295 evaluation above measures certificate verification and keeps its original labels. [Historical module](https://github.com/WeblateOrg/wlc/blob/aafdb507a9e66574ade1f68c50c4fe75dbe80797/wlc/__init__.py#L377) · [Corrected module](https://github.com/WeblateOrg/wlc/blob/a513864ec4daad00146e6d6e039559726e256fa3/wlc/__init__.py#L378) · [Host comparison controls](../../tests/test_python_hosts.py)

The comparison used baseline wheel `97943ddc350026893c2af7661f780582437360533fbc84ad0f7a241e7aa3da3b` and follow-up wheel `b972750e13441bef6e3c59ff03d513f7403bdb500c9d1aa30a68ca6d98220114`. Two fresh follow-up processes produced report SHA-256 `68558ded915783243eda91fd8a465a2e7aa4a7190c8a93602fb7f817cb34db05`. The paired OWASP Python comparison found zero changed outcomes across all 1,230 labels and three scoring channels. All-candidate precision was 89.50% and recall was 100%. [OWASP comparison](try-else-owasp.json)

## Replay

Use the Python interpreter from an environment containing the Aegify wheel and its locked dependencies. The recorded runs used CPython 3.14.7. Set `scanner_python` to that interpreter and `source_cache` to a directory for the upstream files. From this benchmark directory, run

```sh
"$scanner_python" -I evaluate.py --cache "$source_cache" --fetch --output /tmp/tls-first.json
"$scanner_python" -I evaluate.py --cache "$source_cache" --output /tmp/tls-repeat.json
cmp /tmp/tls-first.json /tmp/tls-repeat.json
```

The first command retrieves missing files from the pinned upstream commits. Every run checks the byte count and SHA-256, starts a fresh scanner process per module, and verifies its reported source identity, rule coverage and completion status. The scanner parses source with the model disabled. A changed-byte control stopped before grading.

Both established Python TLS rule IDs participate. Multiple hits on one labeled site count once. Unmatched locations appear under `outside_labels` and need their own review. An incomplete scan produces an unscored label. Exit 0 means all labels agreed, exit 1 indicates a mismatch, and exit 3 indicates incomplete coverage. The recorded candidate returns 1. [Evaluator](evaluate.py) · [Static controls](../../tests/test_python_tls.py)
