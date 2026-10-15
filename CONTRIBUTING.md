# Contributing

This is a maintainer-led alpha with one deliberate purpose: protect one HTTP MCP
server using a pinned issuer, exact resource audience, and additive scope policy,
while keeping client credentials out of the upstream. Discuss material changes to
that boundary in an issue before implementing them. Report vulnerabilities through
the [private security channel](SECURITY.md).

Contributions are accepted under Apache-2.0. Submit only work you have the right to
contribute, preserve third-party notices, and describe the behavior and evidence
behind the change. No contributor license agreement is required. Be respectful,
specific, and constructive in issues and reviews.

## Development

Install `uv` and Python 3.12, clone the repository, and run:

```sh
uv sync --locked --all-groups --python 3.12
uv run ruff check src examples scripts tests
uv run ruff format --check src examples scripts tests
uv run mypy src/mcp_auth_bridge examples scripts
uv run pytest -q
```

CI is configured to repeat the core checks on Python 3.10 and 3.12; passing
results must be confirmed for the revision under review. Add a regression test for a
security or correctness change. Tests should exercise the externally visible
invariant, including rejection before upstream access and cleanup on failure.
Use generated fixture keys and synthetic values; never commit `.env` files,
private keys, real credentials, account identities, or raw browser traces.

Run the HTTP acceptance command in the README and the Keycloak acceptance
command in [the browser demo](docs/browser-demo.md) when a change affects
transport, authentication, discovery, scopes, or the demo. Keycloak tests require
Docker; the deterministic demo does not. Every launcher must stop its owned
processes and free its listeners. Hosted services remain outside this self-hosted release.

For packaging changes, run `uv run python -m scripts.verify_release` and review the
allow-listed report under `artifacts/`. This builds the sdist and wheel, rebuilds
from the sdist, and checks a runtime-only installation outside the checkout.

## Pull requests and releases

Keep changes focused and explain the trigger, resulting behavior, tests run, and
remaining limits. Update the compatibility record when tested versions or behavior
change. Do not claim unexecuted tests, deployed behavior, or broader client support.
Run `graphify update .` after source changes when Graphify is installed; its index
is local and ignored. Maintainers review the change and require CI before merging.
Release and publishing credentials are never available to pull-request jobs.

Versioning and release evidence are described in [provenance](docs/provenance.md).
