# MCP Auth Bridge

**A self-hosted OAuth boundary for one HTTP MCP server.** Developer alpha · Apache-2.0.

MCP Auth Bridge checks access tokens, resource audiences, and required scopes before a request reaches your MCP server. Client credentials stop at the bridge. Your existing authorization server handles login and token issuance.

The first public release is self-hosted. There is no hosted account service. The supported transport is MCP **2026-07-28**; check the [compatibility record](docs/compatibility.md) before connecting a client.

## Set it up with your coding agent

Clone this repository and give your coding agent this prompt:

> Read AGENTS.md and docs/agent-setup.md. Set up MCP Auth Bridge using the locked Python 3.12 environment. Run the Docker-free HTTP acceptance test and stop its services afterward. Then help me configure my public resource URL, issuer, and private upstream. Ask for missing values, keep credentials out of source and reports, and show the configuration check and protected-resource metadata before starting my real bridge. Preserve my existing MCP client configuration.

The instructions work with coding agents that can read a repository and run Python commands. No project-specific agent subscription, plugin, or API key is required. [Detailed agent setup](docs/agent-setup.md).

## Try the local demo — no Docker required

Install [uv](https://docs.astral.sh/uv/getting-started/installation/).

**Intel Mac prerequisite:** the current `cryptography` dependency needs a source
build on this platform. Install Xcode Command Line Tools, Rust 1.83 or newer,
`pkg-config`, and OpenSSL 3 before syncing. See the
[setup guide](docs/agent-setup.md#intel-mac-source-build). Other supported platforms
normally use dependency wheels. The alpha candidate was source-built and checked
on Intel macOS with Python 3.10 and 3.12.

Then run:

```sh
git clone https://github.com/anilpervaiz/mcp-auth-bridge.git
cd mcp-auth-bridge
uv sync --locked --all-groups --python 3.12
uv run python -m scripts.verify_local_demo --report artifacts/http-acceptance.json
```

The verifier launches a loopback test issuer, safe MCP tools, and the bridge. It exercises discovery, permitted calls, rejected tokens/scopes, header checks, credential canaries, streaming, and operations isolation, then stops its services. Reports exclude credentials and are ignored by Git.

For a persistent interactive demo:

```sh
uv run python -m scripts.run_demo
```

In another terminal:

```sh
uv run python -m scripts.verify_demo
```

Press Ctrl+C in the launcher to stop its services. Demo keys are disposable, stay under ignored `.demo/`, and must never be reused outside this example. Required ports are 8000, 8080, 8180, and 9090. The launcher does not replace an existing listener; stop your own conflicting service first.

## Run against your own server

Three configuration values are required:

| Value | Meaning |
|---|---|
| `MAB_PUBLIC_RESOURCE` | Exact MCP resource URL used as token audience, for example `https://mcp.example.com/mcp` |
| `MAB_ISSUER` | Exact issuer configured to mint access tokens for that resource |
| `MAB_UPSTREAM` | Fixed private HTTP MCP endpoint |

```sh
uv run mcp-auth-bridge check-config \
  --public-resource https://mcp.example.com/mcp \
  --issuer https://identity.example.com/realms/mcp \
  --upstream http://private-mcp:8000/mcp

uv run mcp-auth-bridge print-metadata \
  --public-resource https://mcp.example.com/mcp \
  --issuer https://identity.example.com/realms/mcp \
  --upstream http://private-mcp:8000/mcp
```

Use the same arguments with `serve` to start the bridge. Equivalent environment variables are supported; explicit flags take precedence. Defaults bind the bridge to `127.0.0.1:8080` and operations to `127.0.0.1:9090`. For a remote deployment, configure HTTPS termination and the public listener deliberately; keep the upstream and operations listener private.

Production resource and issuer URLs require HTTPS. The optional `--allow-insecure-loopback` exception accepts HTTP only for literal loopback addresses. Configuration checks do not prove issuer availability or correct token issuance; readiness and client acceptance do.

The issuer must provide discoverable trusted keys and signed RS256/ES256 access tokens with the exact issuer/resource and required scopes. By default every call requires `mcp:use`. Add method/tool scopes with `--policy examples/demo/policy.yaml`:

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

Global, method, and tool scopes accumulate. Generic JWT validation cannot distinguish an ID token with otherwise-identical accepted claims; configure the issuer to mint access tokens for this resource.

## Install the release package

The initial version is `0.1.0a2`. Once its matching
[GitHub prerelease](https://github.com/anilpervaiz/mcp-auth-bridge/releases) is
available, verify its artifacts and install the wheel in an isolated tool
environment. If that release has not been published, use the source checkout above.

```sh
uv tool install https://github.com/anilpervaiz/mcp-auth-bridge/releases/download/v0.1.0a2/mcp_auth_bridge-0.1.0a2-py3-none-any.whl
```

This installs the bridge CLI and runtime dependencies. Demos and acceptance tools require a source checkout with development dependencies. [Artifact verification](docs/provenance.md). PyPI publication is deferred.

## Browser sign-in and clients

The optional [Keycloak demo](docs/browser-demo.md) exercises real browser OAuth with the official Python SDK **2.3.0** and separate basic/admin permissions. Its recorded development baseline is distinct from fresh public CI evidence. Only Keycloak uses Docker; the bridge and sample tools run in Python.

The recorded Codex **0.162.0-alpha.17.2** run requires its experimental `mcp_2026_07_28` feature. Older default transports are rejected. Other coding agents can install and configure the bridge; that does not imply their built-in MCP clients support this protocol. [Client setup and tested versions](docs/compatibility.md).

## What the boundary enforces

- Exact issuer and singleton resource audience; finite lifetime claims; asymmetric signatures and additive scopes.
- Bounded issuer/JWKS fetching with vetted DNS destinations, pinned IP connections, original TLS hostname verification, and no redirects or ambient proxies.
- Authentication before body reads; strict JSON and protocol/header agreement; supplied Origin checks.
- Credential, cookie, forwarding, identity, and hop-by-hop header stripping; safe streaming and disconnect cleanup.
- Separate liveness/readiness listener, request/concurrency limits, and safe reason-code diagnostics.

Read the [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [limitations](docs/known-limitations.md), and [security policy](SECURITY.md). This alpha has no production-readiness or availability guarantee. [Contributing](CONTRIBUTING.md) · [Support](SUPPORT.md) · [Changelog](CHANGELOG.md) · [Privacy](PRIVACY.md).
