# Core precision corpus v1

This owned corpus is an executable detection contract, not a claim of universal
scanner accuracy. It pairs positive and negative controls for selected
high-impact taint rules across Python, JavaScript, and Java.

The ground-truth manifest declares the exact rule scope. CI must reproduce its
source-tree digest and achieve precision, recall, and F1 of `1.0` within that
scope. Findings from rules outside the manifest remain visible to normal scans
but do not change this benchmark's denominator.
