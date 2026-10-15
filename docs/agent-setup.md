# Setup with a coding agent

Any coding agent with repository access, a Python environment, and terminal tools
can follow this guide. The agent sets up the bridge; the MCP client you connect
must independently support MCP 2026-07-28. No agent-specific integration is required.

## A prompt to paste

> Clone https://github.com/anilpervaiz/mcp-auth-bridge.git and read AGENTS.md. Install the locked Python 3.12 development environment with uv. Run the Docker-free HTTP acceptance verifier and retain its safe report. Stop the services it starts. Then inspect my available configuration and ask for missing public resource URL, issuer, and upstream URL. Validate the configuration and print protected-resource metadata. Check the chosen MCP client's protocol compatibility before editing its configuration. Preserve other connections, keep credentials out of source/logs, and report exactly what passed and what still needs an identity-provider or user step.

## Expected agent workflow

1. Read README.md, AGENTS.md, and docs/compatibility.md. Inspect existing project
   and client configuration without printing credentials.
2. Confirm uv and a supported interpreter. Use Python 3.12 and `uv sync --locked
   --all-groups --python 3.12`. On an Intel Mac, check the source-build prerequisites
   below before syncing. Any tool/runtime installation follows your agent's ordinary
   permission rules.
3. Check loopback ports 8000, 8080, 8180, and 9090. If another application owns a
   port, explain the conflict; do not kill it or silently reconfigure the example.
4. Run `uv run python -m scripts.verify_local_demo --report artifacts/http-acceptance.json`.
   Expect a passing report and no owned listeners after shutdown. This test uses
   a disposable local issuer and does not prove real browser OAuth.
5. Obtain the three real trust values. The public resource and issuer comparisons
   are exact. The issuer must mint access tokens for that resource with at least
   `mcp:use`; extra method/tool requirements are additive.
6. Run `mcp-auth-bridge check-config` and `print-metadata` using uv or the installed
   release CLI. These commands do not contact the issuer. Show the nonsensitive
   result and identify remaining provider configuration.
7. Start the real bridge only within the requested deployment scope. Default
   listeners are loopback. Remote use needs operator-managed HTTPS, private
   upstream networking, and a private operations listener.
8. Configure only the chosen compatible MCP connection. Use client-owned OAuth
   credential storage. Verify discovery and a safe tool call, rejection before
   upstream, and cleanup. Do not claim arbitrary coding-agent MCP compatibility.

## Intel Mac source build

The `cryptography>=50.0.2` runtime dependency no longer has an Intel macOS wheel;
this platform needs a local source build. Check for Xcode Command Line Tools, a
Rust compiler at least 1.83, `pkg-config`, and OpenSSL 3. If they are missing,
install them through the user's usual toolchain setup. With Homebrew already
installed, the commands are:

```sh
xcode-select --install
brew install rust pkg-config openssl@3
OPENSSL_DIR="$(brew --prefix openssl@3)" uv sync --locked --all-groups --python 3.12
```

Run the first command only when Command Line Tools are absent; macOS may require
the user to complete its installation prompt. Keep the OpenSSL path in the command
environment, never a machine-specific tracked file. Do not pin an older vulnerable
`cryptography` release to avoid the build. Rust is needed to build the dependency,
not to run the bridge. Follow the dependency's
[official installation guidance](https://cryptography.io/en/50.0.2/installation/)
if the platform tools differ. The alpha candidate passed source builds and isolated
runtime installations on Intel macOS with Python 3.10.20 and 3.12.13; its Docker-free
HTTP acceptance also passed with the updated cryptography dependency.

## Information the user supplies

- Public resource URL and exact issuer URL.
- Fixed private upstream URL and applicable scope policy.
- Identity-provider configuration/consent and real credentials through private
  interfaces, never chat transcripts or tracked files.
- Any approval needed to install runtimes, change a client's settings, or expose a
  service. The project supplies no public authorization server.

## Evidence to expect

A source revision/version, runtime/client versions, configuration/metadata checks,
passing test counts, HTTP acceptance outcome, listener cleanup, and explicit
unverified items. Safe reports live in artifacts/. Never include bearer values,
authorization codes, passwords, callback queries, or personal identities.
