# Governance

Aegify is currently maintained by `@Aeg1sx`. The project uses a maintainer-led
model while the contributor base is small.

## Decisions and reviews

- Changes are proposed through pull requests; direct pushes to `main` are for
  repository recovery only.
- Required CI checks must pass before merge.
- Security-sensitive paths are assigned through `.github/CODEOWNERS`.
- A maintainer may request design notes, compatibility evidence, or additional
  negative tests before accepting a change.
- Material architecture, evidence-contract, rule-DSL, or database changes are
  recorded in the pull request and the relevant documentation.

When another active maintainer is added, protected-branch policy should require
at least one approval from a reviewer other than the author. Until then, the
repository administrator retains an audited emergency bypass so the project is
not permanently locked by GitHub's prohibition on self-approval.

## Releases

Releases are cut from protected, signed `v*` tags. The release workflow builds
from the tag, produces an SBOM, and creates a GitHub artifact attestation.
Release notes must distinguish static candidates, observed runtime reachability,
and proved exploit impact.

## Security embargoes

Vulnerabilities are handled in GitHub Security Advisories or private
vulnerability reports. Fix branches, reproductions, and reporter material stay
private until coordinated disclosure. See `SECURITY.md`.

## Changes to governance

Governance changes use the same pull-request and CODEOWNERS review path as code.
The current maintainer may appoint or remove maintainers based on sustained,
constructive participation and security judgment.
