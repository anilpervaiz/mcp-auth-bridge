# Troubleshooting

Start with the status, safe reason code, and `X-Request-ID` when present. Bridge
JSON errors also include `request_id`. Check the exact resource path and listener
port before changing configuration. The bridge can forward upstream error
statuses too; an HTTP status alone does not identify which service rejected a request.

## Setup or local demo does not start

### A port is occupied

The Docker-free demo needs loopback ports **8000, 8080, 8180, and 9090**. The
browser demo also reserves **8765 and 8766**. A launcher refuses to reuse occupied
ports. Do not run the manual launcher and an automated verifier at the same time.

On macOS or Linux with `lsof`, inspect listener ownership:

```sh
lsof -nP -iTCP:8000 -iTCP:8080 -iTCP:8180 -iTCP:8765 -iTCP:8766 -iTCP:9090 -sTCP:LISTEN
```

Stop your previous launcher with Ctrl+C and check again. If another application
owns a port, stop it through its normal controls only when appropriate. Do not use
a broad process-kill command or remove unrelated containers. The demo's fixed
addresses are part of its fixtures; changing one port alone does not reconfigure
the issuer, callback registration, and verifier.

### The verifier says “deterministic local acceptance failed safely”

Inspect `artifacts/http-acceptance.json` for `passed` and cleanup results. The
message intentionally omits raw HTTP and exception details. Confirm the locked
source environment is installed and the ports above are free. Then run the manual
launcher from the [quickstart](quickstart.md#3-keep-the-demo-running-if-needed) to
see which service fails to start. Stop it before retrying the automated verifier.

### Dependency installation fails on Intel macOS

The current cryptography dependency requires a source build on Intel macOS.
Follow the [Intel Mac setup](agent-setup.md#intel-mac-source-build), including
Xcode Command Line Tools, Rust, `pkg-config`, and OpenSSL 3. Set `OPENSSL_DIR` for
the installation command as shown there. Do not replace the supported dependency
with an older vulnerable version. Use the locked Python 3.12 environment for the
first demo; supported Python versions and validation evidence are in
[compatibility](compatibility.md).

### Docker is installed but unavailable

Docker is needed only for the optional Keycloak browser demo. Start Docker
Desktop, wait until its engine is ready, then check `docker info` locally and
retry the launcher. Do not post raw Docker diagnostics without reviewing them for
personal paths and other private data. If the engine cannot start, follow Docker's
supported repair process; a factory reset is not a prerequisite for this project.
The [Docker-free quickstart](quickstart.md) remains usable without it.

## HTTP responses

| Status | Bridge reason or symptom | What to check |
| --- | --- | --- |
| `401` | `authentication_required` or `invalid_token` | Use one Bearer header with an unexpired token from the configured issuer. Check exact issuer and singleton audience, compatible trusted signing key, and supported algorithm. Use the client's OAuth flow to obtain a new token; do not paste it into an issue. |
| `403` | `insufficient_scope` | Compare the challenge's missing scopes with the issuer grant and policy. Global, method, and tool scopes accumulate. The basic fixture user's admin denial is expected. Obtain the appropriate grant instead of weakening the policy. |
| `403` | `origin_denied` | A supplied Origin must match the configured public resource origin. Duplicate, malformed, or `null` origins fail. Inspect the client or reverse proxy that supplied it. |
| `400` | `invalid_request`, JSON/framing error, or protocol/header disagreement | Use a compatible client. Duplicate fields/headers, query-string access tokens, malformed JSON, inconsistent framing, and mismatched MCP headers/body are rejected. A malformed or oversized Bearer header also returns `400`. |
| `404` | Wrong route or operations requested on the public listener | Use the exact configured resource and path-specific metadata URL. Trailing-slash redirects are disabled. `/livez` and `/readyz` belong on the private operations listener. |
| `405` | `method_not_allowed` | This alpha accepts authenticated MCP POST requests. Legacy GET/DELETE transports are outside its scope; a browser navigation is not a supported MCP exchange. |
| `408` | `request_body_timeout` | The request body must arrive within the default ten-second deadline. Check a stalled client or buffering intermediary. |
| `413` | `request_body_too_large` | The default request limit is 1 MiB. Reduce the request size. This is distinct from the 16 KiB token limit. |
| `503` | `trusted_keys_unavailable` or private readiness is `not ready` | Check issuer discovery/JWKS access, exact metadata issuer, usable signing keys, and cache age; see below. |
| `503` | `too_many_requests` | The default ceiling is 32 active protected requests per bridge process. Honor `Retry-After: 1`, reduce concurrency, and check for stalled upstream work. |
| `502` | `upstream unavailable` or `upstream redirects are disabled` | Check the fixed private upstream URL, connectivity, TLS, and response deadlines. Configure the final upstream endpoint rather than relying on redirects. |
| `500` | `internal_error` | Retain the safe request ID and reproduction conditions. Report a possible defect through [support](../SUPPORT.md), or privately through [security reporting](../SECURITY.md) when appropriate. |

Authentication and global scope checks run before the bridge reads the MCP body.
A request with several faults may therefore receive an authentication response
before its malformed body or unsupported method is examined.

## Trusted keys and readiness

`http://127.0.0.1:9090/livez` returns `200` when the operations listener responds.
`http://127.0.0.1:9090/readyz` returns `200` only after startup with usable, sufficiently
fresh trusted keys. Readiness does not prove upstream availability or that a
particular user's token has permission.

For `trusted_keys_unavailable`, check:

- The issuer URL exactly matches the discovery document's `issuer`. Resource and
  issuer strings are not normalized to make mismatches pass.
- The issuer's metadata and JWKS URLs are reachable through the bridge's destination
  checks. Trust fetching does not follow redirects or use environment proxies.
  Disallowed private and link-local destinations are rejected; the explicit
  development exception permits only loopback destinations.
- The JWKS contains a valid verification key compatible with the allowed algorithm
  set, defaulting to RS256 and ES256. An empty or incompatible key set cannot make
  readiness pass.
- Clock and key-rotation configuration are correct. The default key cache is fresh
  for one hour with at most five further minutes of stale use; a refresh cooldown
  never extends that lifetime. Readiness checks age even without request traffic.

The `/readyz` check reads cache state rather than initiating a key refresh.
Authentication requests trigger eligible refresh attempts. After repairing the
issuer, allow the refresh cooldown to elapse and retry through a properly
configured client. `trusted_keys_unavailable` responses include `Retry-After: 60`.
Repeated unknown key IDs are bounded and do not force an unlimited fetch loop.

## Client incompatibility or missing scopes

This alpha validates MCP **2026-07-28**. The official Python SDK **2.3.0** is the
reference client. Compare an installed client's capabilities with the
[client setup](client-setup.md) and [compatibility record](compatibility.md).
Protocol version, method, and applicable name headers must agree with the JSON-RPC
body, including encoded names. Do not remove these checks to accommodate a client
that sends a different protocol.

A token must have `mcp:use` by default. A policy can add method/tool requirements;
all required scopes must be present. The `scope` claim takes precedence over
`scp` when present, and malformed scope syntax is rejected. Whether a client
requests additional scopes automatically is client-specific; SDK step-up evidence
does not prove another client's behavior.

## Streaming stalls or ends early

The bridge forwards raw upstream chunks with backpressure. Check whether the
client or reverse proxy buffers responses and whether the upstream produces data.
The default upstream connect timeout is five seconds and its read inactivity
timeout is sixty seconds. A failure before response headers can produce `502`;
a failure after streaming begins cannot change the already-sent HTTP status.
Treat an incomplete MCP response as a failed exchange even if its status was `200`.

Disconnects cancel upstream work and release the request permit. The Docker-free
HTTP verifier exercises streaming and disconnect cleanup; run it without an
existing manual demo to check the baseline. A passing cleanup report records the
launcher exit. Check listener ownership separately if shutdown appears incomplete.

## Share useful evidence safely

Include the bridge revision/version, Python and client versions, status, safe
reason code, request ID when present, and a minimal reproduction using sample tools.
Attach only reviewed allow-listed reports from `artifacts/`. Do not share Bearer
tokens, passwords, authorization codes, callback query strings, signing keys,
identities, or raw request/response bodies. Review logs from reverse proxies and
identity providers separately; the bridge's safe logging does not control them.
