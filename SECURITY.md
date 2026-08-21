# Security Policy

## Supported versions

CodeGuard is currently alpha software. Security fixes are made on the latest
release and the `main` branch; older releases are not guaranteed to receive
backports.

## Reporting a vulnerability

Please use the repository's [private vulnerability reporting form](https://github.com/Aeg1sx/Aegify/security/advisories/new).
Do not open a public issue containing an exploit, secret, private source code,
or customer scan result. If the form is temporarily unavailable, contact the
maintainer through the GitHub profile without including exploit details in a
public message.

Include only the material needed to reproduce and assess the issue:

- affected version or commit;
- deployment assumptions and required privileges;
- minimal reproduction using an owned fixture;
- expected and observed behavior;
- impact and any known workaround;
- logs or SARIF with credentials and proprietary paths redacted.

Maintainers should acknowledge a complete report within five business days and
coordinate disclosure after a fix or mitigation is available. This is a target,
not a service-level guarantee.

Reports about parser crashes/resource exhaustion, authentication or upload
bypass, cross-project data access, credential disclosure, SSRF, unsafe source
execution, evidence tampering, and dependency/container compromise are in
scope. Scanner false positives or false negatives without a product security
boundary impact should use a normal issue with a synthetic reproducer.

Maintainers will keep the reporter informed of material status changes and
will credit the reporter when requested and legally possible. Public
disclosure timing should be coordinated so users have a reasonable opportunity
to apply a fix or mitigation. This policy is not a bug bounty promise.

## Safe research boundary

Only test systems and repositories you own or are explicitly authorized to
assess. Do not use CodeGuard's future dynamic-validation features against third
party targets without permission. Proof artifacts should demonstrate the
smallest necessary impact and must not contain live credentials or customer
data.

## Deployment notes

- Configure `AUTH_SECRET` and at least one supported identity provider before
  exposing the dashboard.
- Configure a separate `CODEGUARD_UPLOAD_TOKEN` for CI SARIF uploads.
- Keep the dashboard and scanner on a private network unless the deployment has
  an explicit access-control and reverse-proxy policy.
- Run build and validation workloads in isolated, resource-limited workers.
- Treat repositories, build scripts, SARIF, OpenAPI documents, and YAML rules as
  untrusted input.

See the [threat model](docs/THREAT_MODEL.md) and
[data/privacy policy](docs/PRIVACY.md) for trust boundaries and optional
external data flows.
