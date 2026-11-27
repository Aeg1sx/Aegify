# Historical directory check comparisons

The installed Aegify wheel reported an advisory on the changed line in three historical Python functions. It produced zero advisories from `AEG-PATH-003` in those functions after their maintainers changed the checks. Two fresh runs produced byte-identical results. The preceding wheel lacked the rule and scored six unevaluated cases. [Installed wheel results](result.json) · [Preceding wheel results](previous.json)

| Project | Reviewed function | Before | After | Upstream change |
| --- | --- | --- | --- | --- |
| Starlette | `StaticFiles.lookup_path` | Line 172 | Clear | [Starlette commit](https://github.com/Kludex/starlette/commit/1797de464124b090f10cf570441e8292936d63e3) |
| pip | `is_within_directory` | Line 86 | Clear | [pip pull request 13777](https://github.com/pypa/pip/pull/13777) |
| dbt-common | `safe_extract._is_within_directory` | Line 629 | Clear | [dbt-common commit](https://github.com/dbt-labs/dbt-common/commit/e547954a48bac9394ef6eb98432e429dce9a7709) |

The manifest fixes the repository, parent and corrected commits, module, source SHA-256, reviewed function and changed line for each case. Selection and expected locations preceded implementation. The evaluator parses each function's extent, copies the single verified module into a fresh directory and invokes the installed scanner with AI disabled. It verifies the analyzed source digest, rule execution, scan completion, evidence classification and finding locations. Findings outside the selected function have a separate count. The historical packages are only inputs to static analysis. [Case manifest](cases.json) · [Evaluator](compare.py)

These cases demonstrate discrimination around three known maintenance changes. The dbt-common change references the pip work, so the cases include related implementations. Application-wide accuracy, runtime reachability and independent holdout performance require additional evidence. Python documents that `commonprefix` compares characters and recommends `commonpath` for path components. Applications also need to decide how to handle symlinks. [Python path documentation](https://docs.python.org/3/library/os.path.html#os.path.commonprefix)

The broader public OWASP Python run scored all 1,230 labels. Its 425 true positives, 67 false positives, 27 misses and 711 true negatives matched the preceding build case by case. The 90% precision target remains open at 86.38% with 94.03% recall. [Paired Python comparison](python-comparison.json)

## Replay

From the repository root, supply the Python interpreter in an environment containing the installed Aegify wheel. The first command fetches missing source files at the pinned commits. The second uses the cached files offline.

```sh
python3 scanner/benchmarks/directory-boundaries-v1/compare.py "$scanner_python" "$source_cache" /tmp/aegify-directory.json --fetch
python3 scanner/benchmarks/directory-boundaries-v1/compare.py "$scanner_python" "$source_cache" /tmp/aegify-directory-replay.json
cmp /tmp/aegify-directory.json /tmp/aegify-directory-replay.json
```

The evaluator returns 0 for full agreement, 1 for a discrepancy and 3 for incomplete rule coverage. The result records scanner, parser, rules, evaluator and manifest digests. The tested macOS arm64 build used Python 3.14.7 and wheel SHA-256 `027866a7ecfba7d6b3b58ae4ba96307219aa238bd746ac584b12567fabe0f473`.
