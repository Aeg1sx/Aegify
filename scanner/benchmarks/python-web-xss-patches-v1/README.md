# Four XSS patch sites in Python web projects

The current installed wheel identifies one of four original patch sites and produces zero warnings at the four repaired sites. It reports Jupyter Notebook’s default Jinja environment on line 163. All six module scans completed, with zero additional CWE-79 findings outside the labels. The preceding Flask build and its baseline both missed all four originals. [Current installed wheel](jinja-defaults.json) · [Previous Flask build](result.json) · [Initial baseline](previous.json)

The Jupyter case informed this change. The finding is an advisory about an HTML-escaping default. The scanner resolves the Jinja constructor and loader, then follows the environment into the Tornado application settings returned on the default-options path. Explicit caller options can override the default. The repair starts with autoescaping enabled. The rule also handles a local environment that loads an explicitly named HTML template. The two pgAdmin sites and the Flask-Admin helper are still missed. An independent evaluation on new product code remains open. [Source-only controls](../../tests/test_python_jinja.py) · [Jinja autoescaping](https://jinja.palletsprojects.com/en/stable/api/#autoescaping)

| Product and code boundary | Original lines | Repaired lines | Maintainer change |
|---|---:|---:|---|
| pgAdmin cloud deployment error | 131–135 | 132–136 | Encode external error text before the JSON response reaches the UI. [Patch](https://github.com/pgadmin-org/pgadmin4/commit/60d149864b5fdd99675754c7996637737a24fce3) |
| pgAdmin cloud update error | 234–236 | 235–237 | Apply the same encoding to the update error. [Patch](https://github.com/pgadmin-org/pgadmin4/commit/60d149864b5fdd99675754c7996637737a24fce3) |
| Jupyter Notebook template environment | 162–163 | 162–165 | Enable Jinja autoescaping by default while retaining explicit configuration overrides. [Patch](https://github.com/jupyter-server/jupyter_server/commit/35f32dd2da804d108a3a3585b69ec3295b2677ed) |
| Flask-Admin URL validation helper | 135–139 | 141–145 | Normalize the URL before checking the scheme. [Patch](https://github.com/pallets-eco/flask-admin/commit/75e51ebca2c4ef236854cfe88a237177813d39c1) |

The manifest fixes the parent and repair commits, full module digests and inclusive source ranges. These product sites were selected from public maintainer patches, and the previous wheel ran before the scanner changes. Each installed build scanned the same six module versions with AI disabled. Each site scores one primary CWE-79 finding in its specified range. The evaluator also records findings elsewhere in the module. [Pinned inputs](cases.json)

The sample covers three modules and four sites, including two related sites from one pgAdmin patch. It measures location agreement on the selected source files. Cross-file web rendering, product-wide precision and independent label adjudication remain open.

## Replay

Run from the Aegify repository root with the wheel under test installed in the selected Python environment. The first run can fetch the six hash-pinned modules. Subsequent runs can reuse the same cache without `--fetch`. Exit code 1 records missed labels after the evaluator writes the report.

```sh
python -I scanner/benchmarks/transport-verification-v1/evaluate.py \
  --corpus python-web-xss-patches-v1 --cache /tmp/aegify-web-patch-inputs \
  --fetch --output /tmp/aegify-web-patch-results.json
```
