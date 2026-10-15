# Architecture

MCP Auth Bridge acts as one OAuth resource server for one configured MCP resource and forwards approved requests to one fixed upstream.

```text
MCP client
    │ Bearer token + modern MCP request
    ▼
Public listener ── protected-resource metadata
    │ authenticate → authorize → inspect → sanitize
    │             user token ends here
    ▼
Configured MCP upstream

Operations listener (separate loopback port) ── /livez, /readyz
Configured issuer ── RFC 8414/OIDC metadata → vetted JWKS fetcher
```

`BridgeSettings`, `Principal`, and `create_app(settings)` are the initial Python entry points. The command-line runner starts a public app and a separate operations app that share a key cache. The public router has one metadata route and one exact MCP resource route. Unknown paths never become upstream paths.

The configured resource and issuer strings remain unchanged for metadata and token comparisons. RFC 9728 metadata is path-inserted for the protected resource. A pure ASGI middleware owns the exact MCP resource path; the public router serves metadata only. The bridge accepts only asymmetric RS256 and ES256 keys from the configured issuer's JWKS. It checks signed tokens, claims, and policy before forwarding. Request body size is bounded; responses stream with backpressure and bounded buffering. Cleanup follows cancellation.

Issuer metadata and JWKS are fetched through `SafeFetcher`, which resolves all A/AAAA records, rejects forbidden networks, pins the chosen IP for the connection, keeps the original TLS server name, rejects redirects, bounds responses, and does not inherit proxy environment variables. The explicit local-development mode accepts HTTP only for loopback resource/issuer endpoints.

Trust fetches have a ten-second total deadline and a two-second DNS deadline. At most two resolver tasks may be outstanding; a timed-out lookup keeps its slot until the underlying resolver finishes. JSON used for tokens, metadata, JWKS, and MCP requests shares duplicate-member, non-finite-number, and nesting checks. JWKS keys enter the trusted set only when their key type, declared algorithm, curve, and configured algorithm allow-list agree. Readiness and authentication both reject a cache without usable keys. Usability expires from monotonic load time after one hour plus the five-minute stale allowance; refresh cooldown does not extend that window.

Each proxied request owns one idempotent lease for the active-request permit. Once the bounded body is read, one disconnect watcher owns request receive events. It supervises upstream connection, response headers, streaming, cancellation, and cleanup; the response, pool, and permit are released exactly once even when the client disconnects before upstream headers arrive.

## Protocol and policy

The initial transport target is Streamable HTTP version `2026-07-28`. Every protected request is authenticated independently. The bridge requires the protocol-version header, the MCP method header, and the applicable tool/resource/prompt name header to match the JSON-RPC body. It rejects duplicate JSON keys and duplicate protocol headers. Base64 sentinel values are decoded before name comparison.

Policy requirements combine global scopes, method scopes, and matching tool scopes. All are required. The default scope is `mcp:use`. No identity is propagated upstream. The operations listener is not mounted in the public app.

## Local provider sign-in

`scripts/run_oauth_demo.py` owns one pinned, disposable Keycloak container and starts the Python upstream and bridge as loopback processes. It uses a 600-second startup deadline and a bounded asynchronous cleanup path that reaps owned processes and removes its uniquely named container, including cancellation during image startup and readiness waits. `scripts/oauth_client.py` uses the official SDK OAuth provider with a pre-registered public client, in-memory token/client storage, PKCE S256, and a one-shot callback listener on `127.0.0.1:8765`. The SDK performs protected-resource and authorization-server discovery, state and issuer checks, scope step-up, and refresh. One absolute 180-second deadline covers browser navigation, callback, and code exchange. The demo supports both isolated headless Chromium and an isolated visible Chromium window. Redacted evidence records only exact-resource comparisons, token issuer/audience/scope checks, allowed status codes, grant counts, and cleanup results.

Keycloak is configured with the resource-indicator experiment and MCP resource clients whose `resource_url` values are the primary and fixture resource URLs. The public client maps each resource client as its audience. The optional `mcp:admin` client scope is role-mapped to a dedicated realm role granted only to the admin demo user; setup verifies that restriction after import. Basic `mcp:use` and `mcp:execute` scopes remain available to both users. Demo users have placeholder profile fields and reserved `.invalid` email addresses so first sign-in does not pause for profile completion. Recorded development acceptance covered primary and secondary resource indicators, changed code/refresh targets, unknown resources, refresh rotation/replay, basic/admin authorization, and cleanup. The public release must rerun this suite for its own revision; see the [compatibility record](compatibility.md).

## Trust limitations

Issuer configuration is a trust anchor. Generic JWTs cannot always distinguish access tokens from ID tokens when the issuer uses identical audiences and claims; configure the issuer to mint access tokens for the exact resource. Strict RFC 9068 validation, opaque-token introspection, multiple upstreams, and legacy MCP sessions are outside this milestone.

### Dedicated native client boundary

The SDK and Codex use separate pre-registered public clients and exact loopback callbacks (8765 and 8766). Both clients receive the same resource audience mappers and role-filtered optional scopes. Realm setup checks both profiles and client role mappings. Client credentials stay in the client process or Codex credential storage. Native-client transport features must be tested explicitly; the bridge does not translate older protocol requests.


The recorded Codex version performs `server/discover` before listing tools. The demo implements the required modern discovery result with supported versions, tool capability, and server identity; the protected proxy forwards it under the same token and global-scope checks. Recorded Codex 0.162.0-alpha.17.2 requires its experimental 2026 transport flag. Its explicit resource override duplicates the discovered parameter, so this connection relies on resource discovery and retains exact bridge audience validation. Native default scope requests are recorded separately from SDK step-up.

Request forwarding uses an explicit transport-header allow-list. It preserves unknown `Mcp-Param-*` fields, constructs framing and Host itself, and drops all other client-selected headers, including custom API keys and user/email identity headers.
