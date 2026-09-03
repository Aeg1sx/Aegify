# Aegify Dashboard

The dashboard is the authenticated review surface for Aegify findings, evidence
graphs, rule management, scan history, AI suggestions, and auditable triage.

Repository AI scans resolve refs to immutable provider commit SHAs and retain
only model candidates whose file, line, and redacted snippet bind to the fetched
source. They are always advisory. A provider/file/model bound or failed batch is
reported as partial or failed and never causes unseen historical findings to be
marked absent. Project-level absence is reconciled only by an exhaustive,
successful default-branch snapshot.

## Local development

Use the repository-pinned Node and npm versions, then install exactly what is in
the lockfile:

```bash
corepack enable
npm ci
npm run dev
```

Open `http://localhost:3000`. Development may use the documented local auth
path; production deliberately fails closed when authentication, encryption, or
upload credentials are missing.

## Required production configuration

- `AUTH_SECRET`: high-entropy Auth.js session secret.
- `ENCRYPTION_SECRET`: independent secret for encrypted provider credentials.
- at least one configured OAuth provider.
- `AEGIFY_UPLOAD_TOKEN`: dedicated bearer token for SARIF ingestion; do not
  reuse an OAuth client secret or session secret.
- `DATABASE_URL`: persistent production database URL.

Supply secrets through the deployment secret manager, never through committed
files or image build arguments. Rotate upload and provider credentials
independently.

## Verification

```bash
npm test
npm run lint
npm run build
npm audit --audit-level=high
```

The production container runs as a non-root user. Deployment should also keep
the root filesystem read-only where supported, drop Linux capabilities, set
`no-new-privileges`, and terminate TLS at the trusted ingress.
