# Changelog

## 0.1.0a2 — release candidate

- Add the CycloneDX UUID serial number required by the pinned GitHub attestation consumer.
- Check generated inventories with that exact consumer before publication.
- Preserve the public `v0.1.0a1` source tag. Its package release stopped before publishing assets because SBOM attestation failed.


## 0.1.0a1 — release candidate

First public alpha candidate of the self-hosted Python MCP OAuth boundary.
Publication is complete only when the matching tagged release and its verification
artifacts are available; this entry does not itself assert a published package.

- One configured public resource, issuer, and upstream; immutable settings,
  `BridgeSettings`, `Principal`, `create_app`, and configuration/metadata/serve CLI.
- Protected-resource discovery, exact issuer and singleton audience validation,
  RS256/ES256 signatures, bounded trusted-key fetching, and additive scope policy.
- Modern MCP request/header checks, credential stripping, streaming responses,
  disconnect cleanup, and isolated operations endpoints.
- Deterministic and Keycloak browser demos, official SDK acceptance, and a dated
  native Codex compatibility record with explicit experimental feature conditions.
- Python 3.10/3.12 CI, runtime-only wheel installation, typed package marker,
  allow-listed source distributions, reproducible wheel rebuild verification,
  dependency inventory, checksums, and release provenance workflow.
- Portable coding-agent instructions and a Docker-free first-run acceptance path.

Read [known limitations](docs/known-limitations.md) and the versioned
[compatibility record](docs/compatibility.md) for the release's actual boundaries.
