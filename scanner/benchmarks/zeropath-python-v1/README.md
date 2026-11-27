# Python source comparison on the XBOW apps published by ZeroPath

Aegify matched **12 of 33** scorable Python labels on the pinned XBOW applications. ZeroPath’s archived SARIF matched **9 of 33** under the same CWE and source-range rule. The tools shared seven matches. Aegify alone matched five, ZeroPath alone matched two, and both missed 19. These public cases informed development. A separate comparison on three Python web projects missed all four original sites in both builds. [Current findings and controls](flask-return-paths.json) · [Product patch evaluation](../python-web-xss-patches-v1/README.md) · [Previous 10 matches](jwt-signing.json) · [Pinned public archive](https://github.com/ZeroPathAI/validation-benchmarks/tree/9c114481b130b8755d6a56ff5a9c26c7567ded4e)

The new matches are XBEN-008 and XBEN-051. Each view assigns a fixed value on a branch that immediately returns. On the continuing path Aegify follows the earlier value into the response constructor. In XBEN-008 the finding points to construction on line 78 and the trace ends at the return on line 80. XBEN-051 has the same boundary on lines 80 and 82. The XBEN-008 repair adds input checks and now receives a warning on line 78. The archive has no repair for XBEN-051 or XBEN-046. [Paired traces](flask-return-paths.json)

The previous build gained XBEN-005. In the original `app/main.py`, a string literal on line 14 supplies the HMAC key to `jose.jwt.encode` on line 46. The published repair generates the key on line 17. Aegify reports CWE-321 at the original declaration and clears the warning in the repaired file. The rule also recognizes PyJWT’s signing API. Its controls cover aliases, shadowed imports, generated keys and non-HMAC algorithms. [Signing-key tests](../../tests/test_python_signing_keys.py) · [PyJWT API](https://pyjwt.readthedocs.io/en/stable/api.html) · [python-jose signing API](https://github.com/mpdavis/python-jose/blob/master/jose/jwt.py)

Aegify follows selected fields in Flask response formats imported from a scanned Python module containing literal assignments. It resolves aliases and explicit star exports within a repository, checks both source files against their original scan digests, and reports an explicit response constructor or the view return. Dynamic exports and ambiguous module names remain unresolved. In XBEN-046 the scanner reported the return at line 78, outside the supplied label at lines 67–73. The matcher gives this case zero credit. [Flask response controls](../../tests/test_flask_responses.py) · [Evaluator](evaluate.py)

| Case | Rule locations in original source | Rule locations in published repair |
|---|---|---|
| XBEN-005 · JWT signing key | 14 | None |
| XBEN-004 · Flask HTML | 77 | 78 |
| XBEN-008 · Flask HTML | 78 | 78 |
| XBEN-010 · Flask HTML | 73, 79 | 73, 79 |
| XBEN-012 · Flask HTML | 71 | 73 |
| XBEN-013 · Flask HTML | 75 | None |
| XBEN-009 · Django template compiler | 8 | None |
| XBEN-024 · URL download destination | 97 | 101 |

In XBEN-013 an early return prevents control from reaching the reported sink in the repair. In XBEN-012 the repair restricts input characters. The trace records the filter and the warning remains because the surrounding template inserts the value into HTML markup. In XBEN-009 the compiler receives a fixed template in the repair. In XBEN-024 the repair adds an authority allowlist and Aegify still reports the download. The evaluator reads committed blobs as source. [Paired findings](flask-return-paths.json)

The archive contains 39 applications and 43 labels. Seven labels have invalid Python ranges and three lack a Python location. A label scores once when the reported CWE family and at least one supplied location overlap in the same file. The public cases provide no ground truth for additional findings. ZeroPath’s study used a semantic judge, and Corgea published results on another corpus. These runs measure location and classification agreement on the public development set. [Evaluator](evaluate.py) · [ZeroPath methodology](https://eu.zeropath.com/blog/benchmarking-zeropath) · [Corgea methodology](https://corgea.com/blog/we-benchmarked-7-models-on-1913-real-vulnerabilities)

On the pinned OWASP Python corpus, the installed wheel and the preceding JWT build agreed on all 1,230 case records. There were 452 true positives, 53 false positives, zero false negatives and 725 true negatives. All-candidate precision was 89.50% and recall was 100%. Both builds detected all 31 OWASP XSS positives and flagged one of the 58 XSS negatives. [Paired case digests and metrics](flask-return-paths.json) · [OWASP corpus](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba)

## Replay

Use Aegify's installed Python interpreter and a local clone containing the pinned Git objects. The evaluator reads the source, labels and historical SARIF from those objects even if the working tree changes. It needs no API key.

```sh
git clone https://github.com/ZeroPathAI/validation-benchmarks.git /tmp/zeropath-validation
scanner/.venv/bin/python -I scanner/benchmarks/zeropath-python-v1/evaluate.py \
  /tmp/zeropath-validation --output /tmp/aegify-zeropath.json
```

The updated checkout and a separately installed wheel agreed on all 43 label records and all eight original and repair pairs. The result includes the wheel’s SHA-256, scanner fingerprints and case digest. [Current verification](flask-return-paths.json) · [Previous Flask verification](linked-responses.json)
