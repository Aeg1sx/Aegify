# Apache Airflow patch selected after the scanner freeze

The selection protocol and the installed scanner were fixed before querying the advisory index. The wheel SHA-256 is `e889e17c3284cbc087b2b35bb133791e93fad4b9bd3b1b02f81f307cef769228` and the frozen source commit is `fd2e914`. [Selection protocol](protocol.md) · [Development results](../python-web-xss-patches-v1/jinja-defaults.json)

The GitHub Advisory Database returned 17 reviewed PyPI advisories for Apache Airflow and CWE-79 ordered by ascending publication date. The API uses the numeric query parameter `cwes=79`. The literal parameter `cwes=CWE-79` returned an empty list. [GitHub query](https://api.github.com/advisories?ecosystem=pip&affects=apache-airflow&cwes=79&sort=published&direction=asc&per_page=100) · [Parameter documentation](https://docs.github.com/en/rest/security-advisories/global-advisories)

| Candidate in order | Decision |
|---|---|
| CVE-2017-17836, published in the index on 2019-01-25 | Excluded. The Apache notice and the advisory references identify no patch commit or merged pull request. [Apache notice](https://lists.apache.org/thread.html/ade4d54ebf614f68dc81a08891755e60ea58ba88e0209233eeea5f57%40%3Cdev.airflow.apache.org%3E) · [Advisory](https://github.com/advisories/GHSA-9gqg-3fxr-9hv7) |
| CVE-2018-20244, published in the index on 2019-03-06 | Included. Apache confirmed the stored XSS, and the advisory links two commits applying the same patch. The first listed commit is the selected repair. [Apache notice](https://lists.apache.org/thread.html/f656fddf9c49293b3ec450437c46709eb01a12d1645136b2f1b8573b%40%3Cdev.airflow.apache.org%3E) · [Advisory](https://github.com/advisories/GHSA-99cv-8cvv-666c) · [Apache patch](https://github.com/apache/airflow/commit/27a4a888e946728d9bb33b78ec604e08d4a93f89) |

The first eligible production Python file in lexical order was `airflow/www/views.py`. Its first changed HTML expression built the DAG run link at original line 134. The repair escapes the display value and builds the link at lines 134–135. The manifest fixes the full module bytes, both revisions and these inclusive ranges. Selection stopped with this product. [Pre-scan labels](cases.json)
