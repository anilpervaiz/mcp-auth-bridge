# Threat model

## Assets and boundary

The main asset is the client's bearer token. It is accepted by the bridge, validated against a pinned issuer and exact public resource audience, then discarded before the request is sent to the one configured private upstream. The bridge also protects tool operations through scope policy and keeps operational routes on a separate listener.

## Threats and controls

| Threat | Control |
|---|---|
| Token for another API | Exact issuer and singleton audience comparison; no URL normalization |
| Forged, expired, or not-yet-valid token | Asymmetric signature allow-list and explicit time-claim checks |
| Token-selected key endpoint | Select keys only from pinned issuer metadata/JWKS; ignore token URL key hints |
| Compromised/malicious issuer metadata destination | Resolve and validate every address; connect to a vetted IP; no redirects/proxy inheritance; bound response size |
| DNS rebinding | Validate A and AAAA results and pin the selected address for the request |
| Browser DNS rebinding against local listener | Validate supplied Origin against configured public origin; bind local defaults to loopback |
| Header/body mismatch changing the authorized tool | Validate modern method/name/version headers against bounded JSON-RPC body |
| Credential or identity leakage | Strip Authorization, cookies, forwarding, identity, and hop-by-hop headers before upstream; do not propagate identity |
| Client-selected upstream or redirect exfiltration | One fixed upstream URL; never follow its redirects; remove Location/Refresh |
| Streaming resource exhaustion | Request/concurrency caps, body and connect/read limits, backpressure, and one idempotent request lease; a single disconnect watcher supervises the upstream from connection through headers, streaming, and cleanup |
| Client disconnect or cancellation before upstream headers or mid-stream | Close the upstream response and pool and release the active-request permit through the same idempotent cleanup path |
| Slow or endless trust fetches | Ten-second total fetch deadline, two-second DNS deadline, at most two resolver lookups in flight, and bounded document sizes; timed-out DNS work retains its slot until it finishes |
| Malformed or ambiguous JSON | Shared strict parsing rejects duplicate members, non-finite values, malformed shapes, and excessive nesting |
| Permission escalation through malformed scopes | RFC 6749 scope-token validation with ASCII space separators and additive policy checks |
| Demo OAuth callback injection/replay or a slow connection | One loopback-only listener, one absolute 180-second authorization-attempt deadline, duplicate-parameter rejection, bounded callback parsing, and SDK state/issuer validation; listener, accepted connections, and callback tasks are closed on every result |
| Demo basic user requesting admin permission | Keycloak role-mapped `mcp:admin` scope, assigned only through the dedicated admin role; upstream counter verifies pre-proxy denial |
| Operational auth bypass | Liveness/readiness app uses its own listener and routes |
| Secret leakage through logs | Log only generated request IDs and fixed error codes; do not log headers, tokens, identities, bodies, or query strings |

## Assumptions and limits

The operator controls the configured issuer and upstream. The bridge does not make a compromised issuer trustworthy. Generic JWT validation cannot universally distinguish an ID token from an access token when the issuer assigns identical audience and claims; the issuer must mint access tokens for this resource. The initial HTTP exception is restricted to loopback development. Keycloak resource indicators and support for MCP `2026-07-28` are experimental. An explicit private enterprise IdP network allow-list is deferred.

The Keycloak realm, users, passwords, and placeholder profile values are disposable test fixtures. The demo client keeps tokens in memory, binds callbacks to loopback, and uses an isolated browser context for both headless and visible acceptance; no browser credentials, tokens, codes, or callback queries are written to evidence reports.

### Native client verification

Adding a public client is not evidence of correct token issuance. Native acceptance must independently check the authorization resource, issued singleton audience, denial before upstream, expiry-driven refresh, and restart/reconnect. Older transport requests continue to fail strict parsing. Experimental client features are a documented compatibility condition. Native credentials, browser traces, and callback queries must not enter reports or source.

The recorded development compatibility run used the installed Codex app-server without model inference. This is a baseline for the documented client version, not fresh public-release evidence. Other connections are disabled only in the verifier process; on-disk settings are preserved. Discovery data is informational, not a trust anchor. Native credentials remain in Codex storage. The refresh proof waits beyond access-token lifetime plus clock tolerance and permits no additional authorization call; SDK evidence separately counts two rotated refresh grants. Desktop UI reload is not inferred from native-process reconnect.
