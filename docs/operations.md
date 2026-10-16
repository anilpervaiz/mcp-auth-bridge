# Operating a self-hosted bridge

[Documentation index](index.md) · [Configuration reference](configuration.md)

The CLI starts one public application and a separate operations application in
the same process. This guide covers the current alpha's operational behavior;
it is not a production deployment certification or a hosted service recipe.

## Network boundary

| Interface | Default | Intended access |
|---|---|---|
| Public MCP listener | `127.0.0.1:8080` | Your compatible MCP clients, through your HTTPS boundary for remote use |
| Operations listener | `127.0.0.1:9090` | Local/private monitoring only |
| Upstream | Required configuration | Private, fixed MCP server |
| Issuer | Required configuration | Operator-controlled token issuer with discoverable public keys |

The word public describes the application's role; it still binds to loopback by
default. Setting `--host` changes the bind address, not TLS support. For a remote
resource URL, provide HTTPS termination deliberately. Keep the configured resource
and issuer strings exact and preserve the MCP path and required request headers
through the reverse proxy.

Make the upstream reachable only through the intended private network or host
boundary. The bridge removes the client's bearer token and does not add a service
credential or a trusted user header. An upstream that requires its own API key is
not automatically supported by supplying that key in a client request.

Do not publish the upstream directly alongside the protected URL. Do not route
the public reverse proxy to the operations listener. `/livez` and `/readyz` are
not mounted in the public application.

## Health probes

From the bridge host, while the CLI is running:

```sh
curl --fail --max-time 2 http://127.0.0.1:9090/livez
curl --fail --max-time 2 http://127.0.0.1:9090/readyz
```

| Probe | Successful response | Meaning |
|---|---|---|
| `/livez` | `200`, `ok` | The operations application responds |
| `/readyz` | `200`, `ready` | The public runtime started and has usable, unexpired trusted keys |
| `/readyz` when unready | `503`, `not ready` | Startup/trust state is not usable |

Readiness does not prove the upstream is healthy or that an issued token has the
right audience/scopes. Use a compatible client and a safe tool call for that.

## Key freshness and issuer outages

Startup attempts issuer discovery and key loading. The key cache uses one hour
of freshness and allows a further five minutes of stale-key use when refreshing
fails. Authentication and readiness calculate age from a monotonic clock; a
refresh cooldown never extends the total usable window.

There is no periodic background refresh loop in this alpha. Authentication can
trigger a refresh, including for an unknown key ID subject to the shared
60-second cooldown. Readiness observes state; it does not fetch new keys itself.
An idle bridge can therefore become unready when its usable window expires.
A subsequent authenticated request can attempt a refresh, or a normal restart
can retry initial trust loading.

During an outage, previously loaded keys can remain usable only within that
window. Without usable keys, protected requests fail with `503`. An unknown or
invalid token does not become valid because the issuer is unavailable.

For planned issuer key rotation, overlap old and new public signing keys in the
issuer's JWKS long enough for caches and existing tokens to transition. Verify
both readiness and an actual newly issued token. The bridge has no public key
reload or administrative key-management route.

## Limits and capacity

The default is **32 active protected requests per process**, including time spent
reading an accepted request body. Full capacity returns `503` with reason
`too_many_requests` and `Retry-After: 1`. This is not a per-user/minute/day quota
or a distributed rate limiter.

Request bodies are bounded to 1 MiB and have a ten-second read deadline. Upstream
connections have a five-second connect timeout and a 60-second read-inactivity
timeout. The read timeout is not an absolute stream lifetime: a continuously
active stream can remain open. Forwarded response bytes use backpressure, and
client disconnects close upstream resources and recover the request permit.

Metadata/JWKS downloads have separate size, DNS, and total-time bounds. See the
[settings reference](configuration.md) for all values and which are Python-only
settings. Listener/connection capacity is per process, so adding processes also
changes the total possible workload.

## Shutdown and ownership

Use Ctrl+C or a normal process termination signal for the CLI or an owned demo
launcher. The CLI coordinates its two listeners. Demo launchers track their own
Python processes and uniquely named container and perform bounded cleanup.
Do not stop another application merely because it owns a desired port.

For the deterministic and automated browser verifiers, confirm the process exits
successfully and the safe report indicates cleanup. If you launched the persistent
Keycloak demo separately, stop that launcher when finished; the client verifier
does not own it. See [browser demo](browser-demo.md).

Service supervision, restart strategy, edge abuse protection, TLS configuration,
and host/network isolation belong to the operator. Windows service supervision
is not verified.

## Safe diagnostics

Bridge-generated validation errors include a fixed error reason and a generated
request ID; the response header is `X-Request-ID`. Upstream failures may be plain
text rather than the same JSON shape. HTTP status alone cannot identify which
component rejected a request.

The CLI disables Uvicorn access logs. Unexpected request failures log a fixed
message with the request ID, without request contents. Configure any surrounding
proxy, monitor, or logging middleware to avoid recording Authorization, cookies,
bodies, identities, OAuth callback queries, or raw query strings.

Keep diagnostic reports under ignored `artifacts/`. Share the package/client
versions, status, safe reason, and request ID when seeking [support](../SUPPORT.md).
Do not paste an access token into an online decoder or a public issue.

## Before a real deployment

Confirm exact issuer/resource token issuance, additive scope behavior, issuer
network compatibility, a private upstream, a private operations listener, remote
HTTPS, safe shutdown, and the chosen client's protocol support. Use the
[threat model](threat-model.md) and [limitations](known-limitations.md) to evaluate
the remaining assumptions. There is no production-readiness or availability
claim for this alpha.
