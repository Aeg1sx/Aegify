# Worker Preview binding comparison

Wrangler 4.166.0 and the Aegify candidate agreed on **42 of 42** controlled configurations, including both field locations for every shared resource. The previous wheel agreed on 25 and missed all 17 expected advisories. Sixteen involved branch resources and one involved a plaintext Preview variable. Two candidate processes produced identical reports. The earlier local development comparison also retained its 29 expected outcomes. [Previous report](baseline.json) · [Candidate report](reference.json) · [Wheel and replay digests](replay.json)

The runner reads 67 selected Worker environments using Wrangler’s distributed configuration reader. It then runs the same pure functions that assemble Worker Preview request bindings in the pinned bundle. The check uses local JSON and JSONC files, an installed Aegify CLI, and no Cloudflare account. TOML and Pages exclusions are covered by the scanner tests. The comparison lets a reviewer check the manifest interpretation independently of Aegify’s parser. Measuring deployment frequency, data access and accuracy across customer projects requires independent application and deployment evidence. [Source and format tests](../../tests/test_wrangler.py) · [Cloudflare Preview resources](https://developers.cloudflare.com/workers/previews/resources/) · [Cloudflare workflow comparison](https://developers.cloudflare.com/workers/previews/compare-workflows/)

The cases cover separate and shared references, the selected named Worker, top-level inheritance, an empty override, sibling declarations and missing bindings. Controls change development selectors, R2 jurisdiction and Queue producer versus consumer configuration. The runner rejects an unrecognized Wrangler release or bundle digest, missing files, incomplete SARIF and raw fixture identifiers in output.

On the same candidate wheel, the 1,230 public OWASP Python labels retained all case decisions across the all-candidate, blocking and advisory channels. All-candidate precision was 87.60% and recall was 98.45%. The three saved source-assisted AI reviews also reproduced their recorded grades. [Paired OWASP comparison](owasp-comparison.json) · [Saved review inputs and grading](../source-review-v1/README.md)

## Replay

Set the first argument to an installed Wrangler 4.166.0 package directory and the second to an installed Aegify command. The harness creates its own temporary manifests. Exit success requires agreement for every case.

```sh
WRANGLER_SEND_METRICS=false node compare.mjs "$wrangler_package" "$scanner_bin" /tmp/preview-comparison.json
```

Use the optional fourth argument `--baseline` to record a previous build’s disagreements. The two recorded wheels use the same dependency versions and development version string. All 38 distributions in the candidate test environment matched the project lock. Their SHA-256 digests identify the builds.
