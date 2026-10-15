# Security policy

MCP Auth Bridge is an Apache-2.0 alpha. The supported release surface is the
self-hosted Python bridge, its documented configuration, and its CLI. This release does not operate a hosted authorization service. Read the [known limitations](docs/known-limitations.md)
and [threat model](docs/threat-model.md) before evaluating a deployment.

## Report a vulnerability privately

Use [GitHub's private vulnerability report](https://github.com/anilpervaiz/mcp-auth-bridge/security/advisories/new).
Include the affected version, a minimal reproduction using synthetic credentials,
the expected security boundary, and the observed outcome. Do not include live
tokens, authorization codes, passwords, personal identities, or callback query strings.
If the private reporting option is unavailable, open an issue asking for a private
reporting channel without publishing exploit details.

Security reports about authentication bypass, scope enforcement, credential leakage,
unsafe trust fetching, request ambiguity, and resource exhaustion are welcome.
Do not test against infrastructure or identities you do not own or have permission
to assess.

## Support and disclosure

Only the most recent alpha is supported. Fixes may require an upgrade and may change
alpha behavior. Maintainers handle reports on a best-effort basis; there is
no response-time agreement, paid support commitment, or bug-bounty program.
Confirmed issues will be fixed and documented in a release or advisory, coordinating
disclosure with the reporter where practical. Automated tests and scans are evidence
of specific checks, not a security certification or a substitute for deployment review.

Before making the repository public, maintainers must enable private vulnerability
reporting and review the publication checklist in [provenance](docs/provenance.md).
