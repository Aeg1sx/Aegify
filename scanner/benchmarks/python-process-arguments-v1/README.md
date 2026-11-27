# Python subprocess arguments

The installed scanner found six previously missed command-input flows in OWASP Benchmark for Python. Each used a local argument list to pass request data to a shell interpreter. Two fresh scanner processes analyzed the same 1,236 source files and agreed on every one of the 1,230 public labels. AI was disabled. The upstream revision was `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. [Upstream Python corpus](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba) · [Evaluation](python.json) · [Case inventory](python-cases.csv)

| Scope | Build | TP | FP | FN | TN | Precision | Recall |
|---|---|---:|---:|---:|---:|---:|---:|
| All findings | Previous | 445 | 57 | 7 | 721 | 88.65% | 98.45% |
| All findings | Candidate | 451 | 57 | 1 | 721 | 88.78% | 99.78% |
| Blocking | Previous | 182 | 36 | 270 | 742 | 83.49% | 40.27% |
| Blocking | Candidate | 188 | 36 | 264 | 742 | 83.93% | 41.59% |
| Advisory | Both | 345 | 44 | 107 | 734 | 88.69% | 76.33% |

All six recovered cases had a CWE-78 label. The candidate produced a blocking finding on all 13 positives and zero of the seven negatives in that category. Each negative uses an explicit shell option and still receives an advisory. Seven case records lost a redundant rule match and retained the same classification. The single remaining public miss is `BenchmarkTest00984`, labeled CWE-501. The public corpus informed development. The overall 90% precision target and independent application evaluation remain open. [Changes from the previous wheel](python-changes.json) · [Candidate replay](python-replay.json)

## Check exact source locations

The two owned source files contain ten functions. They exercise argument lists built in branches, the value at the time of an append, an independent trailing argument, Windows command text, imported aliases, local aliases, and option-like strings inside ordinary data. The label set specifies 13 expected rule, path and line combinations. The previous wheel matched zero and added two warnings at an unrelated line. The candidate matched all 13 with zero extra findings. Moving one label by one line made the strict gate fail with one false positive and one false negative. [Source fixtures](sources) · [Labels](ground-truth.json) · [Exact SARIF locations from both wheels](owned-comparison.json) · [Owned evaluation](owned.json)

Separate tests compare the scanner's argument selection with Python's standard library for six fixed, benign calls. The test intercepts CPython's process-launch method before a child starts. Other tests cover ambiguous calls, shadowed names and the limits on list reconstruction. [Tests](../../tests/test_python_process.py) · [Python subprocess](https://docs.python.org/3.14/library/subprocess.html#popen-constructor) · [Bash invocation](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html) · [Windows command processor](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)

## Replay

The recorded environment used Python 3.14.7 on macOS arm64. The previous wheel SHA-256 was `6c8a9b210fbc22c32c5da7b87751da4c4c1690c1654d716820ea41e67a3f2e63`. The candidate SHA-256 was `39c3167ade362132a0dbaed39a91c82f079521942a130e29d2567fec520a214c`. From the repository root, set `scanner_bin` to the installed CLI and `corpus_dir` to the pinned upstream checkout.

```sh
suite=scanner/benchmarks/python-process-arguments-v1
"$scanner_bin" benchmark "$suite/sources" --ground-truth "$suite/ground-truth.json" \
  --line-tolerance 0 --min-precision 1 --min-recall 1 \
  --output-file /tmp/aegify-process-controls.json
"$scanner_bin" benchmark-owasp "$corpus_dir" \
  --expected-results "$corpus_dir/expectedresults-0.1.csv" \
  --output-file /tmp/aegify-process-owasp.json
"$scanner_bin" compare-owasp "$suite/python.json" /tmp/aegify-process-owasp.json \
  --baseline-cases "$suite/python-cases.csv" --require-identical \
  --output-file /tmp/aegify-process-replay.json
```

The public evaluation writes the report and exits 1 at the current precision. The strict owned gate and identical public replay both exit 0. CI runs the exact-line check against the newly installed wheel. [CI workflow](../../../.github/workflows/ci.yml)
