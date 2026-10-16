# Browser OAuth demo

This optional local example uses the official Python SDK 2.3.0 and Keycloak 26.8.0.
The recorded development baseline and fresh public release checks are tracked
separately in [compatibility](compatibility.md). Only Keycloak is containerized. Its resource-indicator feature is explicitly enabled
and remains experimental. The test realm, users, and passwords are disposable.

```sh
uv sync --locked --all-groups --python 3.12
uv run playwright install chromium
uv run python -m scripts.run_oauth_demo
```

Start Docker before the launcher. It checks Docker and listener ports, imports the
pinned realm, and waits for readiness. The launcher owns only its uniquely named
container and Python services. Ctrl+C cleans them up.

In another terminal, use a visible isolated Chromium context:

```sh
uv run python -m scripts.oauth_client --scenario basic --visible-browser
uv run python -m scripts.oauth_client --scenario admin --visible-browser
```

The basic scenario lists tools, calls echo, preserves scopes during step-up, and
finishes an admin attempt with 403 and no extra upstream calls. Admin succeeds.
The launcher creates disposable fixture credentials; the automated isolated-browser
modes enter them. Do not reuse fixture accounts, passwords, signing keys, or realm
settings in a real deployment.

For the automated browser suite, stop the manual launcher first:

```sh
uv run python -m scripts.verify_oauth_demo --report artifacts/oauth-acceptance.json
```

This starts and stops its own services. It verifies basic/admin separation, exact
resource audiences, changed/unknown resource rejection, two successive refreshes
using the newest rotated refresh token, and immediate replay rejection. It waits
for actual token expiry, so allow several minutes. Callback-negative cases run
separately in `tests/test_oauth_callback.py`: real-listener lifecycle tests and
SDK wrong-state/issuer tests using injected callback values. See the
[testing guide](testing.md#what-the-regressions-check).

The SDK callback is loopback-only on port 8765, with a 180-second absolute login
deadline. The Codex fixture uses a separate public client and port 8766. Both use
S256 PKCE. Password grants, implicit grants, and offline access are disabled.
SDK credentials remain in memory; Codex owns its credential storage.

The image digest is pinned in the launcher and checked during setup. The demo
requires free ports 8000, 8080, 8180, 8765, 8766, and 9090. It does not repurpose
unrelated containers. A passing report includes cleanup; an unexecuted visible
browser or native-client run must stay marked unverified.

[Documentation index](index.md) · [Client setup](client-setup.md) · [Troubleshooting](troubleshooting.md)
