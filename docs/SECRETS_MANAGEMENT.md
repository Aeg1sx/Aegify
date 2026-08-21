# Secrets management

## Contract

Aegify reads secrets from process environment variables. Source code, images,
examples, SARIF, logs, test fixtures, and Git history must not contain live
credentials. `.env.example` contains names and development placeholders only.

Local `.env*` files are ignored. Generate independent high-entropy values for
`AUTH_SECRET`, `ENCRYPTION_SECRET`, and `AEGIFY_UPLOAD_TOKEN`; never reuse one
secret for another purpose. Rotate a value immediately if it is printed, added
to Git, copied into an issue, or included in a scan artifact.

## GitHub Actions

- Prefer GitHub OIDC for cloud and Vault authentication; do not store long-lived
  cloud or `VAULT_TOKEN` credentials.
- Keep workflow permissions read-only by default and grant write permissions at
  the individual job that needs them.
- Secrets are not passed to pull-request workflows that execute fork-controlled
  code. LLM review is opt-in and must run only from an explicitly approved,
  trusted ref.
- GitHub secret scanning, push protection, Dependabot, and private vulnerability
  reporting are repository controls, not substitutes for rotation.

## HashiCorp Vault

The application does not need a Vault client library. Use Vault Agent, a
sidecar, or the deployment platform to authenticate and inject the exact
environment variables the process needs. `deploy/vault/` contains a minimal
policy and rendering example.

Recommended production flow:

1. GitHub Actions or the workload exchanges its OIDC/JWT identity for a
   short-lived Vault token bound to repository, ref, environment, and audience.
2. A least-privilege policy permits only `read` on the environment-specific KV
   path.
3. Vault Agent renders a mode-`0600` environment file on an in-memory volume or
   exports values directly to the process.
4. The rendered file, token, and Agent cache are never added to images,
   artifacts, logs, or Git.

For local development, copy `.env.example` to a local `.env` and replace the
placeholders. Do not commit the copy.
