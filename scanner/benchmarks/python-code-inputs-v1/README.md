# Python code inputs

The installed scanner cleared six code-injection false positives across 1,230 labeled Python cases. It retained all 445 previous true positives. Two fresh processes scored the same 1,236 source files from OWASP Benchmark for Python at commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. The evaluator had AI disabled. [Upstream source](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba) · [Evaluation](python.json) · [Case inventory](python-cases.csv)

| Scope | Build | TP | FP | FN | TN | Precision | Recall |
|---|---|---:|---:|---:|---:|---:|---:|
| All candidates | Previous | 445 | 63 | 7 | 715 | 87.60% | 98.45% |
| All candidates | Candidate | 445 | 57 | 7 | 721 | 88.65% | 98.45% |
| Blocking | Previous | 182 | 42 | 270 | 736 | 81.25% | 40.27% |
| Blocking | Candidate | 182 | 36 | 270 | 742 | 83.49% | 40.27% |
| Advisory | Both | 345 | 44 | 107 | 734 | 88.69% | 76.33% |
| CWE-94, all candidates | Previous | 20 | 12 | 0 | 21 | 62.50% | 100.00% |
| CWE-94, all candidates | Candidate | 20 | 6 | 0 | 27 | 76.92% | 100.00% |

All six changed cases had a blocking finding on a negative CWE-94 label. Six of the 33 CWE-94 negatives still produce a finding. The public corpus informed development. The overall 90% precision target and independent application evaluation remain open. [Case-by-case comparison](python-changes.json) · [Installed-wheel replay](python-replay.json)

## Check the rule independently

The control harness uses CPython's parser to check the accepted source text in expression and statement mode. Across 14,762 generated inputs satisfying the delimiter checks, both modes yielded a single string literal for 8,680 and rejected 6,082 with a syntax error. A further 11,111 built-in string representations parsed back to their original values. The harness also checks that ordinary arithmetic produces a different syntax tree. These are finite grammar checks. [Control implementation](verify.py) · [Python string literals](https://docs.python.org/3.14/reference/lexical_analysis.html#string-and-bytes-literals)

The harness then sends 13 small source files to the installed scanner and checks the reported rule and line. The previous wheel agreed on eight. The candidate agreed on all 13, including imported and locally assigned aliases, reassignment after a guard, a different input at the call, and a file path using the same guarded value. Every scan completed with zero AI calls. [Previous controls](controls-before.json) · [Candidate controls](controls.json) · [Additional type and scope tests](../../tests/test_python_code.py)

## Replay

The recorded environment used Python 3.14.7 on macOS arm64. The previous wheel SHA-256 was `fc4888b833497b2f8fef8daaafb71667e9d952ac7e04a2523d0ff996a5567f6c`. The candidate wheel SHA-256 was `6c8a9b210fbc22c32c5da7b87751da4c4c1690c1654d716820ea41e67a3f2e63`. Install the candidate wheel and its locked dependencies. From the repository root, set `scanner_bin` to the installed CLI, `scanner_python` to its interpreter, and `corpus_dir` to the pinned upstream checkout.

```sh
"$scanner_python" -I scanner/benchmarks/python-code-inputs-v1/verify.py "$scanner_bin"
"$scanner_bin" benchmark-owasp "$corpus_dir" \
  --expected-results "$corpus_dir/expectedresults-0.1.csv" \
  --output-file /tmp/aegify-code-inputs.json
"$scanner_bin" compare-owasp scanner/benchmarks/python-code-inputs-v1/python.json \
  /tmp/aegify-code-inputs.json \
  --baseline-cases scanner/benchmarks/python-code-inputs-v1/python-cases.csv \
  --require-identical --output-file /tmp/aegify-code-inputs-replay.json
```

The public evaluation writes its report and exits 1 at the current precision. The replay succeeds when the input, implementation and all labeled outcomes match. CI also runs the code-input controls and grades the three saved AI reviews against their frozen source using the newly installed wheel. [CI workflow](../../../.github/workflows/ci.yml) · [Saved review corpus](../source-review-v1/README.md)
