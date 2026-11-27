# HTTP input reaching a regular expression

Both installed scanners analyzed the same source files with AI disabled. The baseline is Aegify `6536ecbc792fc10a5d282ccf13c04d3cd9574693`. The comparison counts distinct file and line pairs for `AEG-A03-011`. It measures source locations, without measuring regex execution time.

| CodeQL query suite | Expected locations | Previous matches | Current matches | Previous extra locations | Current extra locations |
| --- | ---: | ---: | ---: | ---: | ---: |
| Python | 8 | 5 | 8 | 3 | 0 |
| JavaScript with default threat models | 17 | 0 | 1 | 0 | 0 |

The Python suite includes an imported alias, keyword arguments, and three uses of escaped request data. The JavaScript suite has 18 selected rows on 17 distinct lines. The new match is the Express arrow handler in `tst.js`. The missed locations include string methods, legacy Express request accessors, compound data flow and a CLI source. The Python suite was selected before implementation. The JavaScript suite was selected after the initial constructor implementation. These are comparisons with the labeled query fixtures. Neither score estimates the detection rate of a deployed scanner across products. [Python query tests](https://github.com/github/codeql/tree/117209c03510a6197ad0ada8bbce32d402211f32/python/ql/test/query-tests/Security/CWE-730-RegexInjection) · [JavaScript query tests](https://github.com/github/codeql/tree/117209c03510a6197ad0ada8bbce32d402211f32/javascript/ql/test/query-tests/Security/CWE-730/Threat-models-disabled)

## JavaScript callback follow-up

Against the installed package at `d4a466c`, the callback changes increased matches from 1 to 8 of the same 17 JavaScript locations. Extra locations increased from 0 to 3. All three are blocking warnings on escaping transformations in `RegExpInjection.js` at lines 62, 79 and 80. The scanner currently carries the input through those transformations. The new labeled matches are at lines 7, 17, 18, 26, 49, 59 and 82. Nine labeled locations remain undetected. Python retained 8/8 matches with zero extras.

On six Express examples sharing the same URL, the baseline found three pattern flows and the new package found six. The examples cross named, arrow and function-expression handlers with query properties and the legacy request accessor. A separate controlled callback passed a request value through an identity function and a constant-return function into file reads, HTTP requests and regex construction. The baseline reported zero blocking sites. The new package blocked each of the three input-dependent sites. Three SSRF policies reported the same HTTP call. The fixed file path retained a separate advisory from the local file inclusion rule. These are generated controls. [Callback regression tests](../../tests/test_javascript_callbacks.py)

The Geddy file selected before implementation adds a product-code check outside regex review. Both packages missed the documented path traversal in `lib/app/index.js`. The baseline reported four unrelated advisories on each revision. The new package reported eight on each, with zero blocking findings. The comparison used the changed production file from the fix and its parent, with AI disabled. [Geddy patch and parent](https://github.com/geddy/geddy/commit/2de63b68b3aa6c08848f261ace550a37959ef231)

## Product source

* Both packages produced zero warnings from this rule on Django's `django/http/request.py`, `django/urls/resolvers.py` and `django/utils/regex_helper.py`. The router compiles application-supplied URL configuration. These files were selected before implementation. [Django source revision](https://github.com/django/django/tree/d922c68f24e10cab085a6f2200825d3cc29cfd75/django)
* Both packages missed the published markdown2 performance defect in `lib/markdown2.py`. The previous package reported the same five advisories at unrelated locations before and after the patch. The new package produced zero on each side. The fix changes fixed patterns used on Markdown input. This was the first reviewed PyPI CWE-1333 result by publication date with a direct GitHub commit reference in the advisory listing. [markdown2 patch and parent revision](https://github.com/trentm/python-markdown2/commit/7b651260739647de5198323e0445b1618750c374)

## Replay

For each suite, export the files in `inputs.json` from its pinned Git directory to an empty directory. Use a separate directory for each suite. Run the following twice, once per installed scanner, saving each report outside the input directory.

```sh
aegify scan "$sources" --no-llm --severity low --output sarif --output-file "$report"
python3 scanner/benchmarks/regex-pattern-review-v1/compare.py "$suite" "$sources" "$report"
```

Use `python` or `javascript` for the suite. The comparison checks input digests, scan completeness and the source file inventory. It only reads the query's selected results. Paths in the following edge and node tables describe data flow and are excluded.
