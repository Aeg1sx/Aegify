# Core precision corpus v1

This owned corpus is an executable detection contract, not a claim of universal
scanner accuracy. It pairs positive and negative controls for selected
high-impact taint rules across Python, JavaScript, and Java.

The ground-truth manifest declares the exact rule scope. CI must reproduce its
source-tree digest and achieve precision, recall, and F1 of `1.0` within that
scope. Findings from rules outside the manifest remain visible to normal scans
but do not change this benchmark's denominator.

The runner now emits report schema 2, isolates repository/environment configuration,
checks immutable source/labels/implementation and executed scope, and leaves
undefined precision/recall/F1 as null. Output must be outside `sources`. Missing
rules/files or incomplete analysis cannot pass even with perfect observed metrics.
CI repeats this command in two independent processes and compares stable evidence
digests and provenance. This corpus remains owned regression data, not an
independent holdout set or an application-wide accuracy estimate.
