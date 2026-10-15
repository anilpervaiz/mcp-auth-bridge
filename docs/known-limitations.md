# Alpha limitations

- The supported product is a self-hosted Python resource-server boundary for one
  exact resource, one pinned issuer, and one fixed upstream. It does not host login,
  issue tokens, dynamically register clients, or route tenants to arbitrary servers.
- MCP `2026-07-28` is the selected protocol. Legacy GET/DELETE/session transports
  are unsupported. Refer to the dated compatibility record for tested clients;
  the recorded native Codex run requires its experimental modern transport.
- Generic JWT validation cannot distinguish an ID token with otherwise-identical
  accepted claims. The issuer must mint access tokens for the exact resource.
  Strict RFC 9068 token typing is deferred.
- Keycloak resource indicators are experimental. Local fixture credentials are
  deliberately disposable and must never be reused in a deployment.
- Trusted-key fetching validates public destinations and pins vetted IPs with TLS
  hostname verification. Private enterprise issuer allow-lists are not implemented.
  Local HTTP requires the explicit literal-loopback exception.
- Access tokens remain usable until their accepted expiration plus configured
  clock tolerance. There is no opaque-token introspection or immediate revocation
  channel. The issuer and upstream remain operator-controlled trust assumptions.
- Request limits bound one process's work; they are not a distributed Internet
  abuse defense. TLS termination, network isolation of the upstream and operations
  listener, service supervision, and edge abuse controls are operator responsibilities.
- The upstream receives allowed MCP payloads and can return unsafe content. The
  bridge enforces access policy, not tool semantics or output trustworthiness.
- Hosted services and a Workers implementation are outside this self-hosted release.
- Automated checks and the supplied threat model do not establish an independent
  professional security audit, production availability, or compliance certification.

Only the most recent alpha receives best-effort fixes. See [support](../SUPPORT.md)
and [security reporting](../SECURITY.md).
