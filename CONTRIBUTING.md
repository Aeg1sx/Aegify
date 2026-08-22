# Contributing to Aegify

Aegify welcomes focused fixes, language/framework models, rules, fixtures,
documentation, and performance improvements. The project is alpha; changes
should make uncertainty and evidence more visible rather than expanding claims.

## Development checks

```bash
cd scanner
uv sync --extra dev
.venv/bin/pytest -q
.venv/bin/ruff check src tests
.venv/bin/mypy --strict src/aegify

cd ../dashboard
npm ci
npx prisma generate
npm run lint
npm run build
npm audit
```

Run new or changed YAML rules through the strict audit independently:

```bash
cd scanner
aegify audit-rules ../rules/path/to/changed-rule.yml --strict
```

The bundled rule tree must retain zero strict-audit issues. Do not add an
ignored field or copy an unsupported construct into another rule.

## Rules and framework models

Every detection change should include:

- a minimal true-positive fixture;
- at least two close negative fixtures;
- a guarded or sanitized case where applicable;
- supported language and framework versions;
- CWE, source, sink, prerequisite, and impact;
- the expected AST/graph/evidence path;
- a bounded finding count and a performance test for broad matches.

See [the rule contract](docs/analysis/rule-authoring.mdx) before introducing new DSL
fields.

## Security tests

Use synthetic or owned fixtures. Tests must not contact public targets, embed
working credentials, or rely on destructive payloads. Separate a static
candidate from runtime reachability and proved impact in test names and output.

## Pull requests

Keep changes reviewable, document compatibility or migration effects, and list
the exact checks you ran. When changing the Security Graph, SARIF properties,
or Prisma schema, include backward-compatibility handling and a fresh-database
migration test.

All changes target a non-default branch and merge through a pull request.
CODEOWNERS review and required CI apply to security-sensitive paths. Never add
live `.env` files, Vault tokens, customer fixtures, local databases, generated
SARIF, or build caches. See [secrets management](docs/operations/secrets-management.mdx) and
[governance](GOVERNANCE.md).
