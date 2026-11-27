# Session expiry and conditional database writes

The comparison baseline is Aegify `f268b208d5512ae9f0097e120d5fbfebbbe56591`.
The candidate and baseline use their packaged rule sets. These counts cover
`AEG-SESS-002` and `AEG-RACE-004`. The inputs are static source files.

| Upstream input | Baseline | Candidate | What was reviewed |
| --- | ---: | ---: | --- |
| Authlib Starlette Google login example | 2 | 0 | Lines 27 and 55 read or clear an existing session. The middleware is constructed on line 9 with its default maximum age. |
| Passport Express 4 local authentication example | 1 | 0 | Line 30 configures an explicit SQLite session store. The options at this site do not establish its server-side retention policy. |
| Express authentication example | 2 | 1 | Both scanners identify the default MemoryStore configuration on line 22. The additional baseline warning on line 95 concerns a session operation. |
| Apache NiFi before its logout fix | 4 | 0 | The baseline flags other lines in AccessResource. Both scanners miss the published logout issue. |
| Apache NiFi after its logout fix | 4 | 0 | The baseline continues reporting two session and two database warnings in AccessResource. The fixes to token revocation span application components. |

Authlib and Passport were chosen as framework integration controls.
The Express example was selected after detector development as an independent
configuration check. The NiFi fix was selected before implementation from the
first reviewed Maven CWE-613 advisory in ascending publication order with a
linked production change. Its three modified production Java files were scored
at both revisions. These examples do not estimate application-level recall.
[NiFi advisory](https://github.com/advisories/GHSA-fmqw-vqh5-cwq9)

The framework behavior is documented in the
[Starlette middleware](https://github.com/Kludex/starlette/blob/main/starlette/middleware/sessions.py),
[ItsDangerous signer](https://github.com/pallets/itsdangerous/blob/main/src/itsdangerous/timed.py),
[Express MemoryStore](https://github.com/expressjs/session/blob/master/session/memory.js)
and [Jakarta Servlet API](https://jakarta.ee/specifications/platform/9.1/apidocs/jakarta/servlet/http/HttpSession.html).

## Repeating the comparison

Export the listed files from each revision to separate directories, keeping
their repository-relative paths. Check each SHA-256 against the
[input manifest](sources.json). Run both installed wheels with
`aegify scan DIRECTORY --output sarif --output-file REPORT` and write each
report outside the input directory. Compare the rule ID, path and start line.
The owned controls in `scanner/tests/test_session_and_storage_review.py` also
check the finding disposition, source masking and persisted syntax facts.
