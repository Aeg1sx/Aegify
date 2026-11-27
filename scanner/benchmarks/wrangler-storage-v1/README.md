# Wrangler storage binding comparison

The Aegify wheel and Wrangler 4.166.0 agreed on all 29 synthetic manifests. Ten produced a shared-storage advisory at the expected line and 19 stayed clean. Each manifest contains one local development configuration and one independently selected deployment scope.

The comparator passes each file to Wrangler’s configuration reader and its development binding builder. It compares the resolved local storage identifier to the primary identifier in the normalized deployment configuration, including the account and R2 jurisdiction. It separately checks the expected outcome for each fixture, then invokes Aegify’s normal scan command and checks the resulting SARIF. The fixtures cover KV, D1 and R2 preview selection, a separate preview on either side, remote binding opt-in, account inheritance and overrides, and an omitted binding in a named environment. The R2 cases also cover same and different jurisdictions. [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/) · [Workers local development](https://developers.cloudflare.com/workers/local-development/)

From the repository root, use a built Aegify wheel installed in a clean environment and an isolated installation of Wrangler.

```bash
workspace=$(mktemp -d)
npm install --prefix "$workspace" --ignore-scripts --save-exact --no-audit --no-fund wrangler@4.166.0
WRANGLER_SEND_METRICS=false node scanner/benchmarks/wrangler-storage-v1/compare.mjs \
  "$workspace/node_modules/wrangler" /absolute/path/to/venv/bin/aegify "$workspace/reference.json"
```

[Recorded reference](reference.json) includes SHA-256 digests of the installed Wrangler CLI, comparator and fixture inputs, plus each expected source line. The results measure static configuration selection. Production account resolution, resource existence and access require evidence from the installation.

The checked wheel had SHA-256 `b154faebe5230b1a34ab21a97ab30c01cb550eac5c25f9a9924b0e48a2fdbd3c`. npm reported Wrangler package integrity `sha512-qMz0sHGXqEC0Va8T6dAaG0ggp9tCcuHHYMUQzRKbtZg6+MPAPb6oBu1757IaeugNJHPAz+twHiA+zDyXWQLsLw==`.

The final scanner also scored all 1,230 public OWASP Python labels. Its per-case classifications and coverage matched the preceding Python object-reader evaluation. Precision was 86.38% and recall was 94.03%. [Case comparison](python-comparison.json) · [Baseline and reproduction steps](../python-decoders-v1/README.md)
