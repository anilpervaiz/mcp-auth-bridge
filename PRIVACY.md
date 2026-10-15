# Privacy and data handling

The self-hosted Python bridge has no project-operated telemetry or account system.
It processes bearer credentials and bounded MCP requests in the operator's process,
fetches trusted issuer metadata and keys, and sends permitted requests to the fixed
upstream. It does not forward client bearer tokens, cookies, or identity claims.
The upstream receives the permitted tool input, so that input may still contain
sensitive information supplied by the client.

Application diagnostics use generated request IDs and fixed reasons. The provided
launcher disables HTTP access logging. Hosting platforms, reverse proxies, identity
providers, clients, and custom logging integrations have their own data handling
and retention; operators must configure those separately. The bridge does not
control their logs or collect them for the project.

The SDK demos keep OAuth tokens in memory. Native Codex owns its own credential
storage. Local demonstration keys and evidence are ignored by Git. Acceptance
reports contain only allow-listed versions, revisions, outcomes, status codes,
counts, comparisons, and cleanup results. They exclude identities, credentials,
callback queries, browser traces, and raw exception output.

GitHub issues, pull requests, and release reports are public after publication.
Review them before submitting. Use the [security policy](SECURITY.md) for private
vulnerability reporting. This document describes the self-hosted alpha; any future
hosted service needs a separate privacy notice and retention design before launch.
