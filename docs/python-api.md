# Python embedding API

[Documentation](index.md) · [Configuration reference](configuration.md) · [Architecture](architecture.md)

The supported top-level imports for alpha `0.1.0a2` are `BridgeSettings`,
`Principal`, and `create_app`. The package also exposes `__version__`. The bridge
is a self-hosted ASGI resource server; login and access-token issuance belong to
your authorization server.

## Create the public app

Save this as `bridge_app.py` in your application:

```python
from mcp_auth_bridge import BridgeSettings, create_app

settings = BridgeSettings(
    public_resource="https://mcp.example.com/mcp",
    issuer="https://identity.example.com/realms/mcp",
    upstream="http://private-mcp:8000/mcp",
)

app = create_app(settings)
```

Replace the illustrative URLs with your actual trust values. With the package and
its runtime dependencies installed in your environment, an asyncio ASGI server
can run this app, for example:

```sh
uvicorn bridge_app:app --host 127.0.0.1 --port 8080 --no-access-log
```

This runs only the public app. Use the package CLI's `serve` command when you want
the built-in pair of public and operations listeners. External HTTPS termination
and private upstream networking remain your responsibility. See the
[configuration reference](configuration.md) and [operations guide](operations.md).

`create_app(settings) -> starlette.applications.Starlette` constructs the app; it
does not bind a socket, start Uvicorn, read environment variables, or make an
initial network request. Its ASGI lifespan startup loads issuer metadata and
trusted keys. Run the app with lifespan enabled on an asyncio event loop; the
current trust-fetch/proxy implementation uses asyncio internally.

A trust outage does not prevent the app from being constructed or the listener
from starting. Protected requests fail closed when usable keys are unavailable.
Metadata remains available independently. Startup completion alone is not a
readiness or provider-compatibility check.

The public app serves the exact resource path and its path-specific metadata
route. It has no operations routes. Each protected request is independently
authenticated and checked against the policy before it is proxied; the upstream
never receives the bearer token or an asserted client identity. The
[compatibility record](compatibility.md) describes tested clients and the required
MCP `2026-07-28` transport.

## Immutable settings

`BridgeSettings` is a frozen, slotted dataclass. Its three required constructor
arguments are `public_resource: str`, `issuer: str`, and `upstream: str`; all other
fields have defaults. Construction validates URLs, supported algorithms, limits,
timeouts, and listener-port constraints. `ConfigurationError`, a `ValueError`
subclass from `mcp_auth_bridge.config`, reports an invalid configuration.

```python
from dataclasses import replace

from mcp_auth_bridge import BridgeSettings
from mcp_auth_bridge.config import ConfigurationError

try:
    settings = BridgeSettings(
        public_resource="http://127.0.0.1:8080/mcp",
        issuer="http://127.0.0.1:8180/realms/mab-demo",
        upstream="http://127.0.0.1:8000/mcp",
        allow_insecure_loopback=True,
        max_body_bytes=512 * 1024,
        max_concurrent_requests=8,
    )
except ConfigurationError as exc:
    raise SystemExit("Bridge configuration is invalid") from exc

# Build another configuration; do not mutate a running app's settings.
rs256_settings = replace(settings, algorithms=("RS256",))
```

Use the declared field types: strings for URLs/hosts, integers for ports and size
limits, positive numeric seconds for timeouts, and a tuple for algorithms. The
frozen dataclass prevents field reassignment; it is not a runtime type checker
for every possible Python object passed to a field.

Listener defaults are `bind_host="127.0.0.1"`, `port=8080`,
`ops_host="127.0.0.1"`, and `ops_port=9090`. These tell the package CLI where to
listen. `create_app` itself does not consume them to bind sockets; pass bind
addresses to your ASGI server explicitly. The policy defaults to globally
requiring `mcp:use`, and `allow_insecure_loopback` defaults to `False`.
See the [complete limits table](configuration.md#python-only-settings) for every
remaining setting and fixed cache/timing controls.

Settings expose these derived values without network access:

| Member | Result |
|---|---|
| `resource_path` | The URL path, or `/` for a resource without a path. |
| `resource_origin` | `(scheme, hostname, effective_port)` for supplied-Origin checks; default ports are 443/80. |
| `metadata_url` | Canonical path-specific protected-resource metadata URL. |
| `protected_resource_metadata()` | A new dictionary containing resource, authorization servers, bearer methods, and the policy's union of supported scopes. |

```python
metadata = settings.protected_resource_metadata()
assert metadata["resource"] == settings.public_resource
assert metadata["authorization_servers"] == [settings.issuer]
assert settings.metadata_url.endswith("/.well-known/oauth-protected-resource/mcp")
```

Public resource and issuer strings are preserved exactly for token comparisons.
Origin matching separately compares normalized scheme/hostname/effective-port
values. Changing settings requires constructing a new app and managing its
lifecycle; hot reload is not an API feature.

## Set a policy in Python

`Policy` and `load_policy` are available from `mcp_auth_bridge.config`, rather than
the three top-level exports. `Policy` copies its scope collections to frozensets
and its method/name mappings to read-only mappings.

```python
from mcp_auth_bridge import BridgeSettings, create_app
from mcp_auth_bridge.config import Policy

policy = Policy(
    global_scopes=frozenset({"mcp:use"}),
    method_scopes={"tools/call": frozenset({"mcp:execute"})},
    tool_scopes={"sensitive_status": frozenset({"mcp:admin"})},
)
settings = BridgeSettings(
    public_resource="https://mcp.example.com/mcp",
    issuer="https://identity.example.com/realms/mcp",
    upstream="http://private-mcp:8000/mcp",
    policy=policy,
)
app = create_app(settings)

assert policy.required_for("tools/call", "sensitive_status") == frozenset(
    {"mcp:use", "mcp:execute", "mcp:admin"}
)
```

To use the same YAML format as the CLI:

```python
from dataclasses import replace

from mcp_auth_bridge.config import load_policy

settings_with_yaml = replace(settings, policy=load_policy("policy.yaml"))
```

Create `policy.yaml` using the [policy example](configuration.md#scope-policy).
Global, method, and matching name requirements accumulate; all must be present.
The `tool_scopes` name mapping currently also matches prompt names and resource
URIs parsed from the corresponding MCP methods. There is no per-request Python
policy callback or identity propagation hook.

## Principal

`Principal` is a frozen, slotted dataclass representing the result of internal
JWT validation:

| Field | Type | Meaning |
|---|---|---|
| `issuer` | `str` | Validated issuer, exactly equal to the configured issuer. |
| `subject` | `str \| None` | Nonempty string `sub`; absent or null becomes `None`. |
| `client_id` | `str \| None` | Nonempty `client_id` claim when present; malformed values are discarded. No `azp` fallback. |
| `scopes` | `frozenset[str]` | Validated scope tokens from `scope`, or from `scp` only when `scope` is absent. |

The public app keeps this value local to its authentication/policy handler. It
does **not** put a principal on `request.state`, expose it to the upstream, or
provide a supported public token-validation function or middleware extension
hook. The `request.state.request_id` used internally is a correlation identifier,
not an authenticated identity. Internal token/cache helpers are implementation
details, not additional supported embedding APIs.

Constructing `Principal(...)` yourself is just constructing a data object; it
performs no signature or claim validation and must not be treated as proof of
authentication. It contains neither the original token nor the full claims object.
Read the [provider token contract](configuration.md#provider-token-contract) for
validation rules and the generic-JWT/ID-token limitation.

## Lifespan and operations integration

For normal use, prefer `mcp-auth-bridge serve`: it starts the public app and a
separate private operations listener in one process and coordinates their shutdown.
If embedding requires your own server supervisor, the current implementation has
an operations-app factory:

```python
from mcp_auth_bridge import BridgeSettings, create_app
from mcp_auth_bridge.app import create_ops_app

settings = BridgeSettings(
    public_resource="https://mcp.example.com/mcp",
    issuer="https://identity.example.com/realms/mcp",
    upstream="http://private-mcp:8000/mcp",
)
public_app = create_app(settings)
ops_app = create_ops_app(public_app)
```

`create_ops_app` is an implementation-level integration point, not one of the
three supported top-level API exports. These two app objects share the same
in-memory runtime. Your supervisor must serve them on **separate listeners in the
same process**, run the public app's lifespan, and coordinate shutdown. Starting
two unrelated Uvicorn processes does not share this runtime or key cache. Mounting
`ops_app` beneath the public router exposes operations endpoints and breaks the
intended boundary.

The operations app provides `/livez` (`200` while serving) and `/readyz` (`200`
only after public startup with usable, unexpired trusted keys; otherwise `503`).
It does not probe the upstream or refresh keys on readiness requests. Calling the
factory alone starts neither listener. Requests manage and close their upstream
resources, including on disconnect/cancellation; the surrounding server still
owns connections, lifespan, and process shutdown. See [operations](operations.md)
for the supported CLI path and [testing](testing.md) for verification commands.
