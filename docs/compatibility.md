# Alpha compatibility — 2026-10-16

The supported package is the self-hosted Python bridge. Runtime and client support
are separate: a coding agent can set up the repository even when its built-in MCP
client does not support the selected transport.

| Component | Intended support and recorded baseline |
|---|---|
| Python | 3.10 and 3.12 core, typing, and clean package-install checks passed in public CI |
| Platforms | Intel macOS source builds with cryptography 50.0.2 passed on Python 3.10.20/3.12.13; Linux passed public release CI; Windows service supervision is unverified |
| MCP | 2026-07-28 modern HTTP only; exact protocol/method/name headers must match the body |
| Official Python SDK | 2.3.0; deterministic HTTP and headless Keycloak OAuth passed for v0.1.0a2 on Python 3.12 |
| Keycloak | 26.8.0 with pinned image digest; resource indicators explicitly experimental |
| Native Codex | Recorded 0.162.0-alpha.17.2, with experimental mcp_2026_07_28 enabled |
| Other coding agents | Can follow AGENTS.md; native MCP client interoperability requires independent testing |
| Hosted service | Not included |

The published [`v0.1.0a2`](https://github.com/anilpervaiz/mcp-auth-bridge/releases/tag/v0.1.0a2)
implementation is revision `d38d209ef09dbf1deff19f08447989b917fe14ca`. Its fresh public
CI, Security, and Release workflows passed; [testing evidence](testing.md#released-alpha-evidence)
links the exact runs and post-download checks. Native Codex and visible-browser
checks were recorded separately during development; automated Keycloak CI does
not establish either of them on the released revision. A new native build or
client surface requires its own acceptance run.

On Intel macOS, follow the [source-build prerequisites](agent-setup.md#intel-mac-source-build).
The sanitized candidate passed 112 tests, lint, formatting, typing, reproducible
wheel rebuilding, and isolated runtime installation on both Python versions on
Intel macOS. Docker-free SDK HTTP acceptance passed with cryptography 50.0.2.
Fresh GitHub workflow results establish the tagged revision's Linux/provider checks.

## Codex local example

Start the Keycloak launcher described in browser-demo.md. Preserve existing Codex
settings and add only this demo connection:

```toml
[mcp_servers.mab_demo_local]
url = "http://127.0.0.1:8080/mcp"

[mcp_servers.mab_demo_local.oauth]
client_id = "mab-codex-client"
callback_url = "http://127.0.0.1:8766/callback"
callback_port = 8766
```

The recorded installed version duplicates the resource parameter if an explicit
`oauth_resource` override is added, so use discovery for that version. Keep exact
issuer/audience checks enabled. Do not copy this local registration into a real
provider without configuring that provider's exact callback and resource audience.

For a manual native sign-in with that recorded build:

```sh
codex --enable mcp_2026_07_28 mcp login mab_demo_local --scopes mcp:use,mcp:execute,mcp:admin
```

For the separate acceptance verifier, keep the Keycloak launcher running, close
any manual callback flow, and run:

```sh
uv run python -m scripts.verify_codex_demo --report artifacts/native-codex.json
```

The verifier uses the actual installed app-server without model inference. It
checks sign-in, discovery, echo, role-filtered admin denial/success, expiry-driven
refresh, native-process restart/reconnect, and callback-port release. This is
separate from the SDK's incremental scope-step-up and two-rotation proof. The
verifier stops its native processes and callback listener; it deliberately leaves
the separately started Keycloak launcher running. Stop that launcher with Ctrl+C
when finished.

The native version was recorded during development; a fresh run is required to
claim that another Codex build or desktop UI surface works. Desktop UI restart,
cloud clients, legacy transports, and automatic dynamic registration are not
claimed. Default native scopes may include OpenID/roles and all MCP scopes; the
Keycloak role restriction still controls admin permission.

See the official [Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
and [Keycloak MCP guide](https://www.keycloak.org/securing-apps/mcp-authz-server).
The bridge's generic JWT mode cannot universally distinguish an ID token whose
accepted issuer/audience/claims are identical to an access token.

[Documentation index](index.md) · [Client setup](client-setup.md) · [Testing](testing.md)
