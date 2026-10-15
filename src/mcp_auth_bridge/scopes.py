"""OAuth scope-token grammar shared by configuration and signed-token validation."""

from __future__ import annotations


def _valid_token(value: str) -> bool:
    return bool(value) and all(
        character == "!" or "#" <= character <= "[" or "]" <= character <= "~"
        for character in value
    )


def parse_scope_value(value: str) -> frozenset[str]:
    """Parse an RFC 6749 scope value, permitting an empty value but only ASCII separators."""
    if not isinstance(value, str):
        raise TypeError("scope value must be a string")
    if not value:
        return frozenset()
    tokens = value.split(" ")
    if any(not _valid_token(token) for token in tokens):
        raise ValueError("scope value does not follow RFC 6749 syntax")
    return frozenset(tokens)


def validate_scope_token(value: str) -> str:
    if not isinstance(value, str) or not _valid_token(value):
        raise ValueError("scope token does not follow RFC 6749 syntax")
    return value
