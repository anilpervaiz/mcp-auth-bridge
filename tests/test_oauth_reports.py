from __future__ import annotations

import pytest

from scripts.oauth_client import _response_returns_oauth_tokens


def test_token_error_response_contains_no_oauth_credentials() -> None:
    assert _response_returns_oauth_tokens(b'{"error":"invalid_target"}') is False


def test_successful_token_response_is_detected_without_retaining_credentials() -> None:
    body = b'{"access_token":"redacted-in-test","refresh_token":"redacted-in-test"}'

    assert _response_returns_oauth_tokens(body) is True


@pytest.mark.parametrize(
    "body",
    [b"[]", b'{"error":"invalid_target","error":"other"}', b"not-json"],
)
def test_malformed_token_response_cannot_be_reported_as_token_free(body: bytes) -> None:
    with pytest.raises((TypeError, ValueError)):
        _response_returns_oauth_tokens(body)
