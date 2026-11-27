# Java session identifier randomness

Two published Java fixes and the OWASP Benchmark for Java were reviewed using
the normal scanner entry point. The comparison baseline is commit
`cea011a35a9454e93fe0384a5854eb630baadb16`. Both rule packs can flag one use.
The table counts distinct use locations in the changed production Java files.

| Product patch | Previous original / repaired | New original / repaired | Evidence |
| --- | --- | --- | --- |
| OrientDB, development case | 0 / 0 | 1 / 0 | The private generator supplies the ID on line 111. The session map stores the same ID on line 112 and the method returns it. The repair instantiates `SecureRandom` while retaining the declared `Random` type. |
| Jetty 6, held out | 0 / 0 | 0 / 0 | The previous implementation initializes the generator in a different method from the one issuing the ID. The generator lifecycle crosses this detector's method boundary. |

The cases were selected before implementation from the GitHub Advisory Database's
reviewed Maven CWE-330 advisories in ascending publication order. OrientDB was
the first entry with a direct commit link. Jetty was the next distinct server
session-ID advisory with a linked fix. The OrientDB change informed the rule.
Jetty was scored after implementation. These two pairs cover a single
development positive and one held-out miss. [OrientDB advisory](https://github.com/advisories/GHSA-v6wr-fch2-vm5w) · [Jetty advisory](https://github.com/advisories/GHSA-jg2x-r643-w2ch)

## Reproduce the product check

Export the listed production Java files at each parent and fix revision to
four separate directories, retaining their repository-relative paths. Verify
each file's SHA-256 against [the input manifest](java-session-patches.json).
Run `aegify scan DIRECTORY --output sarif --output-file report.sarif` with each
installed wheel, writing the report outside the source directory. Compare the
locations for `AEG-A02-004` and `AEG-CRYPTO-002`. Both rules annotate the same
OrientDB registration. No application code or server is started.

## OWASP Java

The previous scanner matched 199 of 218 CWE-330 positive labels and reported
zero findings at 275 negative labels. The missing paths comprise 18 byte arrays
and one scalar. The byte cases require evidence of an in-place fill and the
encoding of that same buffer. In the scalar case an earlier variable with the
same name has already gone out of scope. The new scanner matches all 218
positives and retains all 275 negatives in this category. All additions are
advisories. The general Java evaluation still includes 126 unscored labels.
