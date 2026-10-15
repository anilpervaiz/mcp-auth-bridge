"""Client-selected API credentials and identity never become upstream authority."""

from mcp_auth_bridge.proxy import sanitized_request_headers, sanitized_response_headers


def test_only_transport_headers_cross_the_request_boundary() -> None:
    raw = [
        (name, b"credential-or-identity-canary")
        for name in (
            b"Authorization",
            b"Cookie",
            b"X-Api-Key",
            b"Api-Key",
            b"X-User-Id",
            b"X-User",
            b"X-Email",
            b"X-Amz-Security-Token",
            b"X-Authenticated-User",
            b"Forwarded",
            b"X-Forwarded-For",
            b"X-Request-Id",
        )
    ]
    raw += [
        (b"Accept", b"application/json"),
        (b"Mcp-Method", b"tools/list"),
        (b"Mcp-Param-Future", b"preserved"),
        (b"Host", b"attacker.invalid"),
        (b"Content-Length", b"9000"),
    ]
    forwarded = sanitized_request_headers(raw, 12)
    assert {name.lower() for name, _ in forwarded} == {
        b"accept",
        b"mcp-method",
        b"mcp-param-future",
        b"content-length",
    }
    assert all(b"canary" not in value for _, value in forwarded)
    assert (b"content-length", b"12") in forwarded


def test_hop_by_hop_nomination_also_removes_allowed_headers() -> None:
    forwarded = sanitized_request_headers(
        [(b"Connection", b"Mcp-Param-Future"), (b"Mcp-Param-Future", b"must-drop")], 0
    )
    assert forwarded == [(b"content-length", b"0")]


def test_response_authentication_metadata_is_removed() -> None:
    raw = [
        (b"Authentication-Info", b"nextnonce=credential-canary"),
        (b"Proxy-Authentication-Info", b"nextnonce=credential-canary"),
        (b"WWW-Authenticate", b"Bearer credential-canary"),
        (b"Content-Type", b"application/json"),
    ]
    assert sanitized_response_headers(raw) == [(b"Content-Type", b"application/json")]
