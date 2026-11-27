# Python reader inputs and cross-file flows

Two fresh processes using the installed wheel each analyzed 1,236 Python files and agreed on all 1,230 public OWASP labels. Both used Python 3.14.7 on macOS arm64 with AI disabled. The public inputs informed development. [Pinned OWASP source](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba) · [Aggregate](python.json) · [Case inventory](python-cases.csv) · [Identical replay](python-replay.json)

| Scope | Build | TP | FP | FN | TN | Precision | Recall |
|---|---|---:|---:|---:|---:|---:|---:|
| All findings | Previous | 451 | 57 | 1 | 721 | 88.78% | 99.78% |
| All findings | Candidate | 452 | 53 | 0 | 725 | 89.50% | 100.00% |
| Advisory | Candidate | 346 | 40 | 106 | 738 | 89.64% | 76.55% |
| Blocking | Candidate | 189 | 36 | 263 | 742 | 84.00% | 41.81% |

Three labeled XML negatives selected fixed documents. Two pickle negatives reached an invalid instruction boundary or EOF after a fixed-width sequence of plain data. The candidate cleared those five warnings. It also traced a query string through a typed helper that copied characters and returned the result to a Flask session assignment. One deserialization positive gained a blocking trace. [Paired outcomes](python-changes.json)

The expansion introduced an advisory on the negative CWE-79 case `BenchmarkTest00364`. Its response uses a project-defined HTML encoder whose output safety the scanner could not establish. The case-level regression gate fails on this advisory. Public precision remains below the 90% target. The scorer also leaves 9,370 findings for a different CWE and 12 findings outside labeled cases unadjudicated. Independent application evaluation remains open. [Previous evaluation](../python-process-arguments-v1/README.md)

## Exact source locations

Three owned files exercise a typed keyword-only argument, a cross-file loop and return, a literal argument and a direct session write. The reader pairs change a selected document or byte source while retaining the same reader. A filename passed to the XML file reader still generates a configuration advisory. The candidate matched all eight labeled rule, file and line combinations with zero extras. The previous wheel matched seven, added three warnings and missed the cross-file session write. Moving one expected location by one line produced one extra and one missed finding. [Sources](sources) · [Labels](ground-truth.json) · [Evaluation](owned.json) · [Controls and recorded flow](controls.json)

Additional tests check Python's argument kinds, a loop with zero iterations, opaque or mutated reader inputs and pickle opcode boundaries through standard-library disassembly. [Argument tests](../../tests/test_python_taint_expressions.py) · [XML tests](../../tests/test_python_xml.py) · [Object-reader tests](../../tests/test_python_deserialization.py)

## Replay

From the repository root, set `scanner_bin` to the installed CLI and `corpus_dir` to the pinned upstream checkout. The candidate wheel SHA-256 was `97943ddc350026893c2af7661f780582437360533fbc84ad0f7a241e7aa3da3b`. The previous wheel SHA-256 was `39c3167ade362132a0dbaed39a91c82f079521942a130e29d2567fec520a214c`. All 38 installed distributions matched the lock.

```sh
suite=scanner/benchmarks/python-reader-flows-v1
"$scanner_bin" benchmark "$suite/sources" --ground-truth "$suite/ground-truth.json" \
  --line-tolerance 0 --min-precision 1 --min-recall 1 --output-file /tmp/aegify-reader-controls.json
"$scanner_bin" benchmark-owasp "$corpus_dir" --expected-results "$corpus_dir/expectedresults-0.1.csv" \
  --output-file /tmp/aegify-reader-owasp.json
"$scanner_bin" compare-owasp "$suite/python.json" /tmp/aegify-reader-owasp.json \
  --baseline-cases "$suite/python-cases.csv" --require-identical --output-file /tmp/aegify-reader-replay.json
```

The public benchmark writes its report and exits 1 at the measured precision. The exact-line gate and identical replay exit 0. CI runs the exact-line gate after wheel installation. [CI workflow](../../../.github/workflows/ci.yml)
