# Quickstart

Run the local demo first, then connect one private MCP server to your own issuer.
This is the self-hosted Python developer alpha, `0.1.0a2`. The first demo needs
neither Docker nor an identity-provider account. It uses disposable signing keys
and the official Python SDK **2.3.0** over MCP **2026-07-28**.

## 1. Install the source environment

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and Git, then:

```sh
git clone https://github.com/anilpervaiz/mcp-auth-bridge.git
cd mcp-auth-bridge
uv sync --locked --all-groups --python 3.12
```

**Intel Mac:** read the [source-build prerequisites](agent-setup.md#intel-mac-source-build)
before running `uv sync`. The current cryptography dependency needs Xcode Command
Line Tools, Rust, `pkg-config`, and OpenSSL 3 on this platform. Keep the supported
dependency version; do not downgrade it to avoid a build.

For setup through any coding agent, use the [portable agent setup guide](agent-setup.md).

## 2. Run the Docker-free acceptance demo

Keep these loopback ports free before starting:

| Port | Owned demo service |
| --- | --- |
| 8000 | Private sample MCP server |
| 8080 | Bridge and protected-resource metadata |
| 8180 | Disposable test issuer and JWKS |
| 9090 | Private liveness and readiness listener |

From the checkout:

```sh
uv run python -m scripts.verify_local_demo --report artifacts/http-acceptance.json
```

The verifier starts the services, waits for readiness, runs the HTTP acceptance
checks, and stops its launcher in cleanup. A successful run prints:

```text
PASS: SDK discovery and calls, token/scope rejection, credential stripping, route isolation, redirects, protocol/Origin checks, streaming, and disconnect cleanup
```

Check that the report has `"passed": true` and
`"cleanup": {"owned_python_processes_reaped": true}`. The latter records that the
launcher exited; it is not an independent port-release check. On macOS or Linux
with `lsof`, inspect the demo listener ports after shutdown:

```sh
lsof -nP -iTCP:8000 -iTCP:8080 -iTCP:8180 -iTCP:9090 -sTCP:LISTEN
```

No remaining demo listeners is the expected result. If a listener remains,
identify its owner before stopping anything. See [troubleshooting](troubleshooting.md).

The report contains allow-listed results and versions. `artifacts/` and the demo's
`.demo/` signing-key directory are ignored by Git. Do not reuse fixture keys or
accounts for a real server. This run proves local token enforcement and transport
behavior; browser login is a separate check.

## 3. Keep the demo running, if needed

For inspection, start the launcher yourself:

```sh
uv run python -m scripts.run_demo
```

In a second terminal, from the same checkout:

```sh
uv run python -m scripts.verify_demo
```

The bridge is at `http://127.0.0.1:8080/mcp`. Its discovery document is at
`http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp`.
The private operations endpoints are `http://127.0.0.1:9090/livez` and
`http://127.0.0.1:9090/readyz`. An unauthenticated request to the MCP endpoint
receives `401`; opening it in a browser is not a tool-call test.

Stop the launcher with **Ctrl+C**. It stops only its owned Python processes.
Stop it before running `verify_local_demo`, which needs the same ports.

For real browser sign-in, follow the optional [Keycloak browser demo](browser-demo.md).
That path requires a working Docker engine for Keycloak and a local Chromium
installation. Client support and the distinction between recorded and fresh
checks are listed in [compatibility](compatibility.md).

## 4. Configure your own bridge

The bridge requires three trust values. Replace these example URLs with your own:

```sh
export MAB_PUBLIC_RESOURCE='https://mcp.example.com/mcp'
export MAB_ISSUER='https://identity.example.com/realms/mcp'
export MAB_UPSTREAM='http://private-mcp:8000/mcp'

uv run mcp-auth-bridge check-config
uv run mcp-auth-bridge print-metadata
```

`check-config` prints `configuration is valid`. Both commands work without
contacting the issuer or upstream, so success validates settings, not connectivity
or an issued token. Flags `--public-resource`, `--issuer`, and `--upstream` override
the corresponding environment variables.

Your issuer must publish compatible trusted signing keys and issue access tokens
with its exact issuer string, the exact public resource as the sole audience,
and at least `mcp:use`. Optional policy requirements add method and tool scopes.
See [configuration](configuration.md) for the policy format and validation rules.

When the issuer and private upstream are ready, start the bridge:

```sh
uv run mcp-auth-bridge serve
```

The default listeners are `127.0.0.1:8080` for the bridge and `127.0.0.1:9090` for
operations. The CLI does not provision HTTPS. Remote use needs operator-managed
HTTPS for the public resource and issuer, a private upstream that clients cannot
reach directly, and a private operations listener. These example settings are not
a complete production deployment recipe. The `--allow-insecure-loopback` option
is an explicit local-development exception; the provided demo supplies it.

Use the [client setup guide](client-setup.md) before changing client settings.
The client must support the pinned protocol and obtain its token from your issuer.
Keep tokens in the client's credential storage. The bridge does not forward them
to the upstream or provide a login/account service.

## Optional: install the release CLI only

Use the [GitHub `v0.1.0a2` release](https://github.com/anilpervaiz/mcp-auth-bridge/releases/tag/v0.1.0a2)
and follow [artifact verification](provenance.md) before installing its wheel.
Availability and checks are established by that release's workflow results.
After verifying a downloaded wheel:

```sh
uv tool install --python 3.12 ./mcp_auth_bridge-0.1.0a2-py3-none-any.whl
mcp-auth-bridge check-config
mcp-auth-bridge print-metadata
```

The last two commands use the three environment values configured above. The
wheel installs the runtime CLI and Python API; the demo scripts require a source
checkout. PyPI installation is not part of this alpha.

Read the [known limitations](known-limitations.md), including generic JWT
validation's inability to distinguish an otherwise identical ID token from an
access token.
