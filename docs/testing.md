# Testing and release evidence

The alpha is tested at several layers: focused regressions, real HTTP with the
reference SDK, browser OAuth with Keycloak, clean package installation, and release
artifact verification. A test file shows intended coverage; a passing run for an
identified revision is the evidence that it executed. Passing checks reduce risk;
they do not prove the bridge is free of bugs.

## Released alpha evidence

The published [`v0.1.0a2` release](https://github.com/anilpervaiz/mcp-auth-bridge/releases/tag/v0.1.0a2)
contains implementation revision
[`d38d209`](https://github.com/anilpervaiz/mcp-auth-bridge/commit/d38d209ef09dbf1deff19f08447989b917fe14ca).
Its public checks completed on **2026-10-15 (UTC)**:

| Evidence | Result for that revision |
|---|---|
| [CI](https://github.com/anilpervaiz/mcp-auth-bridge/actions/runs/38783462699) | Core checks and 112 pytest cases on each of Python 3.10 and 3.12; separate Python 3.12 deterministic HTTP and headless Keycloak jobs passed. |
| [Security](https://github.com/anilpervaiz/mcp-auth-bridge/actions/runs/38783462651) | Redacted full-history secret scan and clean-environment runtime dependency audits on both Python versions passed. |
| [Release](https://github.com/anilpervaiz/mcp-auth-bridge/actions/runs/38784169037) | Source/wheel verification, exact-consumer SBOM validation, provenance/SBOM attestations, and six published assets passed. |

The 112 cases include parametrized inputs. Running them on two interpreters does
not make them 224 unique tests. HTTP and provider scenarios are additional jobs.
Current branch checks may cover a newer documentation revision; use the tag and
release manifest when assessing the shipped package.

Post-publication checks also verified the five checksum-listed assets, verified
build attestations for all six downloaded assets and wheel/sdist SBOM attestations, installed
the downloaded wheel outside the checkout on Python 3.10.20 and 3.12.13, and ran
actual HTTP acceptance with the installed Python 3.12 wheel. Temporary environments
were removed and the demo listener ports were checked after shutdown. The
allow-listed local report is not included in the package; the public release and
workflow links above are the reproducible public record.

Visible-browser and native Codex runs were recorded separately during development.
They are not rerun by the headless Keycloak CI job. See [compatibility](compatibility.md)
for the exact native build and limitations.

## Run the core checks

From the source checkout with [uv](https://docs.astral.sh/uv/getting-started/installation/):

```sh
export UV_PYTHON=3.12
uv sync --locked --all-groups --python "$UV_PYTHON"
uv run python --version
uv run ruff check src examples scripts tests
uv run ruff format --check src examples scripts tests
uv run mypy src/mcp_auth_bridge examples scripts
uv run pytest -q
```

Repeat the whole block with `export UV_PYTHON=3.10` to exercise the other supported
interpreter. Keep that variable set for every check: `.python-version` otherwise
selects 3.12 again on a later `uv run`. Set `UV_PYTHON=3.12` and resync before
running SDK/provider acceptance. Syncing changes the checkout's development environment.
Intel macOS needs the [source-build prerequisites](agent-setup.md#intel-mac-source-build).

### What the regressions check

| Area | Failure scenarios and invariant | Test source |
|---|---|---|
| Tokens and policy | Wrong issuer/audience, invalid lifetime/signature/algorithm, malformed scopes, and additive permissions are rejected before upstream access. | [Core](../tests/test_core.py), [hardening](../tests/test_hardening.py), [HTTP acceptance](../scripts/verify_demo.py) |
| JSON and protocol | Duplicate fields, non-finite numbers, excessive nesting, duplicate headers, encoded names, and header/body disagreements fail safely. | [Core](../tests/test_core.py), [wire fixtures](../tests/test_wire_parity.py) |
| Trusted keys and fetching | Rotation/outage, stale expiry during cooldown, readiness without traffic, incompatible keys, bounded unknown-key floods, trickle downloads, and retained timed-out DNS slots. | [Hardening](../tests/test_hardening.py) |
| Proxy lifetime | Disconnect before upstream headers and during streaming closes the real TCP upstream and restores exactly one concurrency permit. | [Proxy lifecycle](../tests/test_proxy_lifecycle.py) |
| Header boundary | Custom credential/identity canaries and hop-by-hop nominated headers are stripped; upstream authentication response headers are removed. | [Header boundary](../tests/test_request_header_boundary.py) |
| OAuth callback | Real-listener tests reject duplicates and cover cancellation, timeout, slow connections, and cleanup. Separate SDK tests reject injected wrong state/issuer values. | [Callback](../tests/test_oauth_callback.py) |
| Provider and launcher | Exact public-client callbacks, S256, role restrictions, owned-container cleanup, cancellation, and refusal to replace unrelated listeners. | [Realm](../tests/test_oauth_realm.py), [launcher](../tests/test_oauth_launcher.py), [ports](../tests/test_demo_ports.py) |
| Packaging and reporting | Archive allow-lists, malformed members, optimized-Python release checks, safe reports, and preservation of unexpected output files. | [Release safety](../tests/test_release_safety.py), [reports](../tests/test_oauth_reports.py) |

The proxy-lifecycle tests use the complete ASGI app and a real TCP upstream but
replace token validation to isolate lifecycle behavior. Authentication is checked
elsewhere. Some Docker lifecycle failure tests simulate Docker; real provider
acceptance separately runs the pinned container. Wire fixtures exercise the Python
implementation; a Workers implementation is not shipped or verified by this release.

## Run actual HTTP acceptance

```sh
uv sync --locked --all-groups --python 3.12
uv run python -m scripts.verify_local_demo --report artifacts/http-acceptance.json
```

This needs free ports 8000, 8080, 8180, and 9090, but no Docker or provider account.
It starts a disposable issuer, bridge, and sample MCP server, then uses SDK 2.3.0
for discovery, listing, and tool calls. Negative requests must leave the upstream
call count unchanged. Credential canaries, route isolation, redirects, protocol and
Origin checks, chunks arriving before completion, and 32 disconnected streams are
also checked. The launcher is stopped afterward.

Require `passed: true` and successful cleanup in the report. Its process-cleanup
flag records launcher exit; independently check listener ownership as described in
the [quickstart](quickstart.md#2-run-the-docker-free-acceptance-demo). Do not equate
a report being written with the checks passing.

## Run browser OAuth acceptance

Start a working Docker engine, stop any existing demo launcher, then:

```sh
uv sync --locked --all-groups --python 3.12
uv run playwright install chromium
uv run python -m scripts.verify_oauth_demo --report artifacts/oauth-acceptance.json
```

Linux CI installs browser system dependencies with `playwright install --with-deps chromium`.
The verifier owns its unique Keycloak container and Python services. It needs ports
8000, 8080, 8180, 8765, 8766, and 9090. Allow several minutes: refresh checks wait
for actual access-token expiry.

The pinned SDK 2.3.0/Keycloak 26.8.0 scenarios prove:

- Basic sign-in, listing and echo, additive scope step-up, and an admin denial
  ending in `403` without another upstream call; admin-user access succeeds.
- Exact resource parameters and singleton audiences, including a secondary fixture
  resource. Changed code/refresh resource bindings and unknown-resource code
  exchange require `400 / invalid_target` with no tokens. An unknown authorization
  resource must issue no tokens and can be rejected earlier through an
  `invalid_target` authorization callback; its report status is synthesized as
  `400`, rather than an observed token-endpoint response.
- Exactly two successful refresh exchanges using the latest rotated refresh token,
  with no intervening browser authorization or authorization-code exchange.
  Previously granted scopes and the audience survive each issuance.
- Old-refresh-token replay returns `400 / invalid_grant` in a separate session,
  which is then discarded.

Require `passed: true` and all three cleanup results:
`verifier_launcher_exited`, `owned_processes_reaped`, and `owned_container_removed`.
The callback-negative cases in the table above run in pytest, separately from
this provider harness. See [browser demo](browser-demo.md) for a visible run and
[client setup](client-setup.md) for native Codex verification. Stop the separately
started launcher after those manual checks.

## Verify packaging and security

```sh
uv run python -m scripts.verify_release --python 3.12 --output-dir dist/check-312 --report artifacts/release-312.json
uv run python -m scripts.verify_release --python 3.10 --output-dir dist/check-310 --report artifacts/release-310.json
```

Use dedicated output directories. The verifier refuses unexpected files rather
than deleting them. It checks exact archive membership, rebuilds an identical wheel
from the sdist, installs runtime dependencies outside the checkout, constructs the
app, and runs both configuration commands. No services start during these checks.
A dirty-tree report is development evidence only, not publishable release evidence.

[Security CI](../.github/workflows/security.yml) runs Gitleaks 8.30.1 against Git
history and pip-audit 2.10.1 against newly installed runtime dependencies on both
interpreters. No findings are ignored to obtain a pass. Dependency results are
time-specific; future installations may resolve newer versions within the runtime
requirements. Never treat a Linux/Python 3.12 inventory as a universal platform lock.

[Provenance](provenance.md) explains downloading artifacts, verifying checksums and
attestations, and distinguishing an inventory from a vulnerability assessment.

## Bugs the checks caught

Regression work found custom credential/identity headers could cross the proxy
boundary; the request allow-list and canary checks now cover that path. Dependency
auditing also blocked an older cryptography dependency with known advisories. The
alpha uses the updated dependency rather than suppressing those results.

Release integration caught a separate defect: the first release attempt's SBOM
lacked the UUID expected by the pinned GitHub attestation consumer. `0.1.0a2` adds
that identifier and validates with the consumer before publication. The earlier tag
is preserved; its failed publication is not presented as a successful release.

## Limits and safe evidence

There has been a separate agent review of authentication/proxy boundaries, but no
independent professional security audit. Missing dedicated regressions include a
live wrong-host TLS-certificate fixture, repeated outer-task cancellation during
cleanup, and wrong-state/issuer cases combining the real listener with the SDK.
The latter SDK regressions inject callback values rather than sending them over TCP. Broad client interoperability, Windows service supervision, and production
deployments remain unverified. No hosted soak or free-tier capacity measurement is
claimed. See [known limitations](known-limitations.md).

Reports belong in ignored `artifacts/` and contain allow-listed versions, revisions,
status codes, scenario results, comparison booleans, grant counts, and cleanup results.
Review them before sharing. Never include tokens, authorization codes, passwords,
identities, callback query strings, raw exceptions, or browser traces. Public CI
reports have limited retention, so published source and release attestations remain
the durable references; do not commit private evidence to preserve it.
