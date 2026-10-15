# Agent instructions

MCP Auth Bridge is a self-hosted Python OAuth resource server. Start with README.md,
then docs/agent-setup.md. The public API is BridgeSettings, Principal, and
create_app(settings); preserve these and the existing CLI's three trust values.

## Setup and verification

- Use uv and Python 3.12 for the default environment: `uv sync --locked --all-groups --python 3.12`.
  On Intel macOS, read the source-build prerequisites in docs/agent-setup.md first;
  do not downgrade cryptography to bypass a missing compiler or OpenSSL installation.
- Run the Docker-free acceptance: `uv run python -m scripts.verify_local_demo --report artifacts/http-acceptance.json`.
- Run core checks before code changes are finalized: Ruff lint/format checks,
  mypy for src/mcp_auth_bridge examples scripts, and pytest. Python 3.10 and 3.12
  are the recorded baseline. Do not rewrite uv.lock without a dependency change.
- Account for the real client's protocol support. The bridge requires MCP
  2026-07-28 metadata and matching headers; do not weaken this to make an older
  client pass. See docs/compatibility.md.
- Do not start Docker just to run the basic demo. Browser OAuth checks need
  Docker/Keycloak and isolated Chromium; follow docs/browser-demo.md when requested.

## Configure a real bridge

Inspect available project configuration before asking. Ask for any missing public
resource URL, exact issuer, or private upstream URL. Never invent them. Check
configuration and print metadata before starting the service. Verify that the
issuer mints access tokens for that exact audience and requested scopes; an
existing ID-token login is not sufficient evidence. Keep the upstream and
operations endpoint private. Preserve other MCP client registrations.

## Credentials and ownership

Never commit or print live credentials, tokens, private keys, callback queries,
identities, or sensitive request bodies. Keep local keys in ignored .demo/ and
safe results in ignored artifacts/. Do not store personal paths in documentation.
Never terminate unrelated listeners. Track and stop processes/containers started
by your test, including failures. Check listener release before reporting success.

## Changes

Keep security boundaries explicit. Add meaningful regression tests for behavior
changes, run applicable acceptance checks, and report passed/unrun checks separately.
Read docs/threat-model.md before changing token validation, trust fetching, scopes,
headers, proxy lifecycle, or operations routes. Read SECURITY.md for vulnerability
reporting. If graphify-out/GRAPH_REPORT.md exists, consult it for architecture and
run `graphify update .` after source changes; Graphify is optional and never a
prerequisite for installing this package.
