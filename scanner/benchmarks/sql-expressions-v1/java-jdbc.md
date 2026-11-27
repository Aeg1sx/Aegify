# Java JDBC query review

`AEG-SQL-002` inspects the SQL text passed to JDBC. When code prepares a
statement, it reports the construction at the prepare call and records the
origin lines. Binding another placeholder in the same query can leave that
construction in place. A fully parameterized query and its bound values are
covered by separate regression controls. The finding is advisory.

The scanner resolves explicit imports and fully qualified JDBC types, servlet
request reads, string parameters, local aliases, and the non-null input path
through a literal null default. It follows typed `DataSource.getConnection()`
and `Connection.createStatement()` calls, including local `var` declarations.
Ambiguous assignments, wildcard imports, fields, custom wrappers, lambda
captures and cross-method string construction remain outside this analysis.
A string parameter alone does not establish caller control. The JDBC APIs
document the SQL-text arguments. [Connection](https://docs.oracle.com/en/java/javase/25/docs/api/java.sql/java/sql/Connection.html) · [Statement](https://docs.oracle.com/en/java/javase/25/docs/api/java.sql/java/sql/Statement.html)

## Public benchmark

The baseline is `92b7d761e465472babc857ddcc8f5c3592ffa538`. Use the same
pinned Java sources and unmodified labels with each installed scanner wheel.
Both scans use the default static benchmark configuration. The outcome is
scored once per case and CWE. [Corpus manifest](../beta-quality-v1/java-corpus.json)

```sh
aegify benchmark-owasp "$JAVA_CORPUS" --language java \
  --expected-results "$JAVA_CORPUS/expectedresults-1.2.csv" --output-file "$REPORT"
```

| All candidate findings | Detected positives | Missed positives | False positives | True negatives |
|---|---:|---:|---:|---:|
| Java CWE-89 baseline | 21 | 251 | 12 | 220 |
| Java CWE-89 candidate | 24 | 248 | 12 | 220 |
| All scored Java cases, baseline | 481 | 851 | 29 | 1,253 |
| All scored Java cases, candidate | 484 | 848 | 29 | 1,253 |

The three recovered cases are `BenchmarkTest00024` (read line 44, prepare at 53),
`BenchmarkTest00027` (read 44, update at 52), and `BenchmarkTest00439` (read 43,
query at 53). Every other Java case and all 1,230 Python case outcomes match
the baseline. Java still has 126 unscored labels. The SQL recall is 8.82% on
these 272 public positive cases. Blocking outcomes are unchanged.

## Product patch check

The product check uses the eleven modified `src/main` Java files from the
GeoTools fix for CVE-2023-25158. Export their original repository paths at
parent `424f4f03888da7257d0f775b48b9d3c1acbd0f6f` and fix
`64fb4c47f43ca818c2fe96a94651bff1b3b3ed2b` into separate empty directories.
Scan each directory with each wheel and count CWE-89 findings. This is one
public patch, selected after development began. [Maintainer advisory](https://github.com/geotools/geotools/security/advisories/GHSA-99c3-qc2q-p94m) · [Patch](https://github.com/geotools/geotools/commit/64fb4c47f43ca818c2fe96a94651bff1b3b3ed2b)

Both scanners completed all eleven files on each side. The baseline produced
zero CWE-89 findings. The candidate reported the same statement in
`PostGISDialect.java` before and after the fix (lines 1356 and 1365).
The expression and JDBC call at that location are unchanged. Neither scanner
identified the advisory's patched code. The additional finding's input trust
has not been adjudicated.
