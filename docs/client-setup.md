# Connect an MCP client

This guide connects a client to the self-hosted alpha. The bridge checks requests;
your authorization server performs sign-in and issues access tokens. There is no
hosted sign-in service in this release.

Client transport support is separate from installing the bridge or using a coding
agent to set it up. The supported transport is **MCP 2026-07-28**. The bridge checks
the protocol version and matching method/name headers and request metadata.
An older client can reach discovery and still fail when it sends a tool request.
See the [tested versions and evidence](compatibility.md).

## Choose an installation path

| What you installed | What you can run |
|---|---|
| Release wheel | The production bridge CLI and Python embedding API |
| Source checkout with development dependencies | The bridge, official SDK demo clients, acceptance verifiers, and optional Keycloak demo |

The wheel does not install the SDK demo or the development dependencies. To use
the commands below, start in a source checkout and install its locked environment:

```sh
git clone https://github.com/anilpervaiz/mcp-auth-bridge.git
cd mcp-auth-bridge
uv sync --locked --all-groups --python 3.12
```

On Intel macOS, complete the [source-build prerequisites](agent-setup.md#intel-mac-source-build)
before syncing. The examples use the official Python SDK **2.3.0** supplied by the
locked development environment.

## Official Python SDK: first prove HTTP connectivity

Run the complete Docker-free example:

```sh
uv run python -m scripts.verify_local_demo --report artifacts/http-acceptance.json
```

It starts a disposable loopback issuer, sample MCP server, and bridge. Through the
official SDK, it discovers the server, lists tools, and calls echo. It also checks
rejected tokens and permissions, credential stripping, streaming, and private
operations routes. It stops the services it started before returning.

A passing result establishes this local HTTP path. Browser OAuth is a separate
check. The test requires free ports **8000, 8080, 8180, and 9090**; it does not replace
an unrelated listener.

The [HTTP client implementation](../scripts/verify_demo.py) uses the SDK's
streamable_http_client with Client configured for **mode="2026-07-28"** and
**cache=None**. Keep the explicit mode when adapting that example. Do not replace
it with an older transport or manually omit the matching MCP headers.

## Official Python SDK: browser sign-in and refresh

Follow the [Keycloak browser-demo guide](browser-demo.md) for Docker prerequisites,
the pinned image, and disposable realm setup. Only Keycloak runs in a container.

After starting Docker, use one terminal for the owned services:

```sh
uv run playwright install chromium
uv run python -m scripts.run_oauth_demo
```

Wait for the launcher to report readiness. In another terminal, run these
separately to see isolated browser sign-in:

```sh
uv run python -m scripts.oauth_client --scenario basic --visible-browser --report artifacts/sdk-basic.json
uv run python -m scripts.oauth_client --scenario admin --visible-browser --report artifacts/sdk-admin.json
```

Both scenarios list tools and call echo. The basic scenario requests additional
scopes but its admin call ends in **403**, with the upstream call count unchanged.
That denial is an expected successful test result. The admin scenario reaches the
admin tool. The visible examples fill the disposable fixture credentials; they
are not a provider-neutral login client.

To exercise exactly two automatic refreshes while the same launcher is running:

```sh
uv run python -m scripts.oauth_client --scenario refresh --headless --refreshes 2 --report artifacts/sdk-refresh.json
```

This waits for real access-token expiry, uses the latest rotated refresh token,
preserves granted scopes, and forbids browser fallback during the refresh phase.
Allow several minutes.

For the full automated provider suite, first stop the manual launcher with
**Ctrl+C**, then run:

```sh
uv run python -m scripts.verify_oauth_demo --report artifacts/oauth-acceptance.json
```

The verifier starts and cleans up its own services. It covers basic/admin
permissions, resource binding, two refreshes, and a separate replay test.
Negative callback cases such as wrong state/issuer, duplicate parameters, and
timeout are separate core regressions; see the [test guide](testing.md).

The [OAuth client implementation](../scripts/oauth_client.py) delegates discovery,
PKCE, scope step-up, and refresh to the SDK's OAuthClientProvider. It stores tokens
and client information in memory for that process. Its pre-registered public
client is **mab-sdk-client**, with exact callback
**http://127.0.0.1:8765/callback** and a 180-second authorization deadline. The demo
resource is **http://127.0.0.1:8080/mcp**.

These modules are fixed to the disposable Keycloak fixture. For your own provider,
implement the SDK's storage and browser callback interfaces, register your own
exact public-client callback, and use your resource URL throughout authorization,
code exchange, refresh, and token audience validation. Changing only the demo
endpoint is insufficient. Keep real tokens and callback query strings out of
source, shell arguments, reports, and logs.

## Recorded native Codex example

The recorded native baseline is **Codex 0.162.0-alpha.17.2**, using its experimental
**mcp_2026_07_28** feature. These steps reproduce that baseline; they do not claim
support for every current Codex version or for the desktop UI. Check your installed
version before trying it:

```sh
codex --version
```

Keep the Keycloak launcher running. Its realm includes a separate pre-registered
public client, **mab-codex-client**, using S256 PKCE and the exact callback
**http://127.0.0.1:8766/callback**. This is distinct from the SDK's port 8765.

Preserve your existing Codex configuration. Add or update only this demo
connection in your Codex configuration file, normally **~/.codex/config.toml**:

```toml
[mcp_servers.mab_demo_local]
url = "http://127.0.0.1:8080/mcp"

[mcp_servers.mab_demo_local.oauth]
client_id = "mab-codex-client"
callback_url = "http://127.0.0.1:8766/callback"
callback_port = 8766
```

For that recorded build, leave **oauth_resource** unset: its explicit override
duplicates the resource parameter already supplied through discovery. Exact
issuer and audience validation remain required.

The recorded manual sign-in command is:

```sh
codex --enable mcp_2026_07_28 mcp login mab_demo_local --scopes mcp:use,mcp:execute,mcp:admin
```

Codex owns credential storage; do not paste tokens into the TOML configuration.
Enabling the feature for this command does not configure another running Codex
process or establish desktop UI compatibility.

For actual native tool-call acceptance, close any manual callback flow and run:

```sh
uv run python -m scripts.verify_codex_demo --report artifacts/native-codex.json
```

The verifier enables the experimental transport on its own app-server processes
and uses isolated visible browser contexts. It checks discovery, echo, basic/admin
permissions, expiry-driven refresh, native-process restart/reconnect, and callback
port release without requesting model inference. It leaves the separately started
Keycloak launcher running; stop that launcher with **Ctrl+C** afterward.

The native verifier records Codex's default requested scopes. That evidence is
distinct from the SDK's incremental scope step-up and two-refresh proof. Requesting
an admin scope does not grant it to a basic user. A different Codex build requires
a fresh native acceptance run before claiming compatibility.

## Connect to your own deployment

Use your exact public resource URL for the client endpoint. The bridge still
requires three operator settings: public resource, exact issuer, and fixed private
upstream. Follow the [bridge setup guide](agent-setup.md) to check the configuration
and metadata before starting it.

Your provider must issue supported asymmetric access tokens for that exact
resource with **mcp:use** and any additional method/tool scopes. The bundled demo
policy adds **mcp:execute** for tool calls and **mcp:admin** for sensitive_status.
Pre-register the client's exact callback and confirm resource-indicator support;
dynamic client registration is outside this alpha.

A **401** response normally directs a compatible client to discovery/sign-in.
A **403** can mean insufficient scopes or a rejected Origin. A **400** can indicate
a malformed request or protocol/header disagreement. Check safe reason codes and
the required scopes; do not fix these failures by disabling audience, scope,
Origin, or transport validation.

Keep the upstream and operations listener private. The bridge forwards transport
headers rather than client credentials or identity headers; a tool requiring its
own upstream credential needs an operator-controlled design. Read the
[known limitations](known-limitations.md), including the generic-JWT limitation
for an otherwise-identical ID token, before using the alpha with your own issuer.

Reports under **artifacts/** contain safe outcomes, not credentials. A successful
local command, public CI run, visible-browser run, and native-client run are
different evidence; claim only the checks you actually executed.
