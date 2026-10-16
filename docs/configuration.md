# Configuration reference

[Documentation](index.md) · [Python API](python-api.md) · [Operations](operations.md)

This reference describes the self-hosted Python alpha `0.1.0a2`. One bridge protects
one exact resource URL, trusts one issuer, and forwards approved requests to one
fixed upstream. Start with the [setup guide](agent-setup.md) for installation.

## Required trust values

| CLI flag | Environment variable | Meaning |
|---|---|---|
| `--public-resource` | `MAB_PUBLIC_RESOURCE` | Public MCP URL and the exact audience accepted in access tokens. |
| `--issuer` | `MAB_ISSUER` | Exact authorization-server issuer, also required in issuer metadata and tokens. |
| `--upstream` | `MAB_UPSTREAM` | Fixed private MCP endpoint that receives approved requests. |

All three are required, including for `check-config` and `print-metadata`. A
nonempty explicit flag takes precedence over its environment variable. An empty
flag falls back to the environment; it does not clear a value. Python construction
does not read these variables automatically.

The resource and issuer strings are compared exactly. A trailing slash, different
case, explicit default port, or different URL spelling can change the expected
claim. Set the issuer to its advertised `issuer` value and configure access-token
audiences to match the resource string exactly.

Each URL must be absolute HTTP(S), with a host and no embedded credentials, query,
or fragment. Port zero is rejected. Resource and issuer require HTTPS by default;
the fixed upstream may use HTTP on a private network. Upstream requests always use
the configured endpoint; incoming paths and query strings do not select a target.

```sh
export MAB_PUBLIC_RESOURCE='https://mcp.example.com/mcp'
export MAB_ISSUER='https://identity.example.com/realms/mcp'
export MAB_UPSTREAM='http://private-mcp:8000/mcp'

mcp-auth-bridge check-config
mcp-auth-bridge print-metadata
mcp-auth-bridge serve
```

These are illustrative addresses; replace them with your own three values. In a
source checkout, prefix commands with `uv run`.

## Commands and CLI options

| Command | Behavior |
|---|---|
| `serve` | Start the public and operations listeners in one process. This is the default if the command is omitted. |
| `check-config` | Validate local settings and policy, then print `configuration is valid`. It does not contact the issuer or upstream. |
| `print-metadata` | Validate settings and print the protected-resource metadata as JSON. It does not check provider compatibility or key availability. |

Successful configuration commands exit with `0`. Argument and configuration
errors exit with `2`. Startup failures and interrupted service operation are
separate from a successful configuration check.

| Option | Default | Purpose |
|---|---|---|
| `--public-resource URL` | Required; environment fallback above | Exact public resource and token audience. |
| `--issuer URL` | Required; environment fallback above | Trusted issuer. |
| `--upstream URL` | Required; environment fallback above | Fixed upstream. |
| `--policy PATH` | `MAB_POLICY`, otherwise the default policy | Read a YAML scope policy. A nonempty flag overrides `MAB_POLICY`. |
| `--allow-insecure-loopback` | Off | Explicit HTTP development exception for loopback resource/issuer URLs. |
| `--host HOST` | `127.0.0.1` | Public listener bind address; independent of the advertised resource URL. |
| `--port PORT` | `8080` | Public listener port. |
| `--ops-host HOST` | `127.0.0.1` | Separate operations listener bind address. Keep it private. |
| `--ops-port PORT` | `9090` | Operations listener port. |
| `-h`, `--help` | — | Print command usage and exit. |

Only the four `MAB_*` variables listed above are read by the CLI. There are no CLI
flags or environment bindings for the Python-only limits below. Listener ports
must be between `1` and `65535`; identical public and operations bind addresses
and ports are rejected.

`serve` binds loopback by default even when the resource URL uses a public domain.
The CLI does not configure TLS certificates. Arrange HTTPS termination and routing
for a remote deployment, and keep the upstream and operations listener isolated.
See [operations](operations.md).

## Loopback development

```sh
mcp-auth-bridge check-config \
  --public-resource http://127.0.0.1:8080/mcp \
  --issuer http://127.0.0.1:8180/realms/mab-demo \
  --upstream http://127.0.0.1:8000/mcp \
  --allow-insecure-loopback
```

The exception recognizes loopback IP literals and `localhost`; an arbitrary DNS
name pointing at loopback does not qualify for an HTTP URL. Trust fetching still
checks every resolved address. With this flag enabled, issuer metadata and JWKS
fetches are restricted to loopback destinations, including HTTPS fetches. Do not
use it to combine a local HTTP resource with a public issuer. Without it, trust
fetches require HTTPS and public network destinations; private enterprise issuer
allow-lists are not implemented.

This command only validates configuration. The [browser demo](browser-demo.md)
starts the example issuer, and the [Docker-free demo](../README.md) uses a separate
deterministic test issuer.

## Scope policy

The default policy requires `mcp:use` for every protected request. A YAML file can
replace the global list and add method/name requirements:

```yaml
policy:
  default_scopes: [mcp:use]
  methods:
    tools/call:
      require: [mcp:execute]
  tools:
    sensitive_status:
      require: [mcp:admin]
```

Use `--policy policy.yaml` or set `MAB_POLICY=policy.yaml`. The only top-level key
is `policy`; its allowed keys are `default_scopes`, `methods`, and `tools`.
Method/name rules accept either a scope list or `{require: [...]}`. Scope names
are case-sensitive and must follow RFC 6749 scope-token syntax: nonempty printable
ASCII excluding spaces, double quotes, and backslashes. Unicode whitespace is not
a scope separator.

Requirements accumulate; no rule overrides an earlier requirement:

| Request | Scopes required by this example |
|---|---|
| `tools/list` | `mcp:use` |
| `tools/call`, name `echo` | `mcp:use`, `mcp:execute` |
| `tools/call`, name `sensitive_status` | `mcp:use`, `mcp:execute`, `mcp:admin` |

All required scopes must be present. Global requirements are checked before the
request body is read; method/name rules follow bounded body and protocol checks.
Omitting `default_scopes` retains `mcp:use`. An explicit `default_scopes: []`
removes that baseline, while authentication remains required. An empty method or
name list does not remove global requirements.

In this alpha, `tools` is a mapping against the parsed MCP name: tool names for
`tools/call`, prompt names for `prompts/get`, and resource URIs for `resources/read`.
A matching entry therefore also applies to a prompt or resource with that exact
name/URI. Method rules remain additive. This is a scope-requirement policy, not an
allow-list of permitted MCP methods or tool names; unmatched requests retain the
global requirements and any matching method rule.

## Provider token contract

The bridge validates signed JWTs; it does not issue tokens, run login, register
clients, or introspect opaque tokens. Configure your provider as follows:

| Item | Accepted behavior |
|---|---|
| Discovery | RFC 8414 issuer metadata first; OIDC discovery is tried only after `404` or `410`. Metadata `issuer` must exactly equal the configured issuer and supply `jwks_uri`. |
| Signature | `RS256` or `ES256` by default, verified using trusted public JWKS keys. RSA keys require at least 2048 bits; ES256 uses P-256. |
| Key selection | `kid`, when supplied, must be a nonempty string selecting exactly one eligible key. Without `kid`, exactly one key eligible for the token algorithm must exist. |
| Header | `alg` must be enabled. `crit` is rejected. Optional `typ` must be `JWT`, `at+jwt`, or `application/at+jwt`. Token-supplied key locations do not establish trust. |
| `iss` | Required string, exactly equal to `issuer`. |
| `aud` | Exact resource string, or a one-item array containing it. Multiple audiences are rejected. |
| `exp` | Required finite numeric date; booleans and numeric strings are rejected. |
| `nbf`, `iat` | Optional finite numeric dates. `nbf` cannot be too far in the future; `iat` cannot be too far in the future. |
| Time tolerance | Fixed 30 seconds for expiry, `nbf`, and `iat`. There is no configurable maximum token age or TTL. |
| Scopes | A `scope` string, falling back to `scp` only when `scope` is absent. Missing or empty values grant no scopes. Arrays, tabs, repeated/leading/trailing spaces, and Unicode whitespace are rejected. |
| Other claims | Absent or null `sub` becomes `None`; any other value must be a nonempty string. An absent or malformed `client_id` becomes `None`; `azp` is not used as a substitute. |

JWT headers/claims, metadata, JWKS, and MCP bodies reject duplicate JSON members,
non-finite numbers, and excessive nesting. A valid signature alone does not grant
permission. The issuer must mint access tokens for this exact resource: generic
JWT validation cannot distinguish an ID token with otherwise-identical accepted
claims. See the [limitations](known-limitations.md) and [threat model](threat-model.md).

## Python-only settings

Use [`BridgeSettings`](python-api.md) to change these values. Limits apply within
one bridge process, not across a deployment. Sizes are bytes; timeouts are seconds.

| Field | Default | Meaning |
|---|---|---|
| `max_token_bytes` | `16384` (16 KiB) | Maximum bearer-token size. |
| `max_body_bytes` | `1048576` (1 MiB) | Maximum buffered request body. |
| `max_metadata_bytes` | `262144` (256 KiB) | Maximum response body for each issuer metadata/JWKS fetch. |
| `max_jwks_keys` | `32` | Maximum number of candidate keys in a JWKS response, before filtering. |
| `max_concurrent_requests` | `32` | Maximum protected requests holding a permit during body reads and proxy work. |
| `body_timeout` | `10.0` | Total request-body read deadline. |
| `connect_timeout` | `5.0` | Upstream connection timeout. |
| `upstream_read_timeout` | `60.0` | Upstream read inactivity timeout, not a total response deadline. |
| `trust_fetch_timeout` | `10.0` | Total deadline for each metadata/JWKS HTTP fetch, including DNS. |
| `dns_timeout` | `2.0` | Deadline for a trust-fetch DNS lookup. |
| `algorithms` | `("RS256", "ES256")` | Nonempty selection from these two supported algorithms. |

Size/key/concurrency values must be positive. Timeout values must be finite,
positive numbers, not booleans. There are no settings for identity propagation,
extra upstream credentials, additional issuers/upstreams, wildcard audiences, CORS,
or a different MCP protocol revision.

The following controls are fixed in the current implementation: trusted keys have
a one-hour fresh interval plus up to five minutes of stale use, with a 60-second
refresh cooldown; unknown-key results have a 30-second negative cache bounded to
256 entries; at most two DNS lookups may remain outstanding. Timed-out lookups
retain their slots until they finish. Readiness checks expiry directly and does
not refresh keys; authentication can trigger a bounded refresh.

## Discovery and failures

For `https://mcp.example.com/mcp`, public metadata is served at
`https://mcp.example.com/.well-known/oauth-protected-resource/mcp`. It advertises
the exact resource, one authorization server, header-based bearer authentication,
and the union of policy scopes. It is not proof that keys or the upstream are
available. The protected path requires authenticated POST requests conforming to
MCP `2026-07-28`; the public app does not mount `/livez` or `/readyz`.

| Status | Bridge-generated cause |
|---|---|
| `400` | Malformed/duplicate Authorization header, token too large for the header limit, query `access_token`, invalid framing/JSON, or protocol/header disagreement. |
| `401` | Missing token or invalid token; includes a Bearer challenge with the metadata URL and baseline scopes. |
| `403` | Invalid supplied Origin or missing required scopes. Scope failures include an `insufficient_scope` challenge listing missing scopes. |
| `404` | A path outside the configured resource and metadata routes. |
| `405` | Unsupported HTTP method after successful authentication/global scope checks. |
| `408` | Request-body deadline exceeded. |
| `413` | Request body too large. |
| `502` | Upstream connection/protocol/timeout failure before response headers, or an upstream redirect. |
| `503` | No usable trusted keys (`Retry-After: 60`) or all request permits occupied (`Retry-After: 1`). |
| `500` | An unexpected internal request failure; report it using safe request diagnostics. |

Protected-request validation errors return `error` and `request_id` JSON fields;
proxy failures use a safe plain-text message. Once upstream response headers have
been sent, a later stream failure cannot change the HTTP status. Origin checks
precede authentication; authentication/global scope checks precede method/body
validation, so a request with several defects may receive the earlier failure.
The upstream may return its own status after approval. See [operations](operations.md)
for readiness, logging, and troubleshooting.
