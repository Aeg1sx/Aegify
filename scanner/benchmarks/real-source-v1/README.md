# Pinned external-source coverage checks

These are static source-only smoke evaluations. No application was installed or
started, no vulnerability payload was executed, and no source was sent to a model.
`results.json` records exact upstream commits, source/archive/artifact digests,
scanner commit, configuration, coverage, gaps and local timing context.

| Corpus | Analyzed files | Result | Recorded findings | Coverage limitations |
|---|---:|---|---|---|
| Juice Shop `1618a611` | 309 | Partial | 788 advisory, 10 blocking | 2 unsupported shell files; per-rule cap omitted 52 findings |
| DVWA `b496a5d3` | 9 | Partial | 19 advisory, 0 blocking | 168 in-scope PHP files unsupported; archive contains 169 PHP files before exclusions |

Finding disposition is the scanner's gate decision. None of these counts has
been independently adjudicated into true or false positives. Precision, recall,
accuracy, TP, FP and FN are explicitly `null`. Do not rank detectors or make a
product accuracy claim from these smoke evaluations. Timings are single local
runs with concurrent host work, not a controlled performance baseline.

## Replay

1. Check out the scanner commit recorded in `results.json` and synchronize its
   lockfile with the required uv version.
2. Obtain each official upstream source archive at its recorded full commit.
   Extract with path and size checks; do not install dependencies or run scripts.
3. Confirm the canonical source-tree digest with
   `aegify.quality.benchmark.digest_source_tree`.
4. Scan from the scanner environment:

```bash
AEGIFY_SCAN__MAX_WORKERS=2 aegify scan /path/to/extracted/source \
  --no-llm --severity low --output sarif --output-file result.sarif
```

Exit `3` is expected for these configurations. Retain the report and read the
coverage gaps. A zero-finding partial result must never pass a clean-scan gate.

## Next evaluation gates

- Establish independently reviewed labels tied to commit, file/range, rule/CWE,
  prerequisite, expected evidence path and nearby negative cases.
- Separate supported backend/frontend code from explicitly excluded shell code.
  Evaluate the complete supported Juice Shop scope with output caps disabled and
  report the changed resource budget and denominator.
- Add a separately tested PHP parser/semantic contract or an external analyzer
  adapter before scoring DVWA's backend. JavaScript utility scans do not cover it.
- Freeze calibration and held-out sets; report per-rule/language/CWE metrics,
  confidence intervals, coverage, abstention and repeated-run AI review quality.
- Measure p50/p95 latency and peak memory on fixed hardware, then compare cached
  and clean runs for identical source-bound evidence.
