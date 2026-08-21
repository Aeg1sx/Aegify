# Vault integration example

These files are reviewed templates, not a deployed Vault configuration.

- `policies/codeguard-dashboard.hcl` grants read-only access to one KV v2 path.
- `templates/codeguard.env.ctmpl` shows Vault Agent rendering the dashboard's
environment variables.

The production dashboard fails closed unless the secret payload supplies
`AUTH_SECRET`, `ENCRYPTION_SECRET`, and one complete GitHub or GitLab OAuth
client pair. `CODEGUARD_UPLOAD_TOKEN` remains a separate machine credential.

Bind the production auth role to the exact repository and protected ref. For a
GitHub OIDC/JWT flow, validate issuer, audience, repository owner, repository,
and `refs/heads/main` or the release environment. Do not accept arbitrary fork
claims and do not expose a reusable `VAULT_TOKEN` as a GitHub secret.

Mount the rendered file on a memory-backed volume with mode `0600`, source it
only in the dashboard process, and revoke the token when the workload exits.
Change the sample KV mount/path to match the deployment before applying it.
