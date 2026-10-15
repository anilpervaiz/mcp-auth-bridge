"""Strict JSON decoding shared by the token, trust, and protocol boundaries."""

from __future__ import annotations

import json
import math
from typing import Any


class StrictJSONError(ValueError):
    """JSON was ambiguous, non-finite, invalid UTF-8, or too deeply nested."""


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError("duplicate JSON member")
        result[key] = value
    return result


def _finite_float(value: str) -> float:
    try:
        result = float(value)
    except (ValueError, OverflowError) as exc:
        raise StrictJSONError("invalid JSON number") from exc
    if not math.isfinite(result):
        raise StrictJSONError("non-finite JSON number")
    return result


def _reject_constant(value: str) -> None:
    raise StrictJSONError(f"invalid JSON constant: {value}")


def _check_depth(text: str, max_depth: int) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > max_depth:
                raise StrictJSONError("JSON nesting limit exceeded")
        elif char in "]}":
            depth -= 1


def strict_loads(data: str | bytes, *, max_depth: int = 64) -> Any:
    """Decode UTF-8 JSON, rejecting duplicate keys and values JSON cannot represent safely."""
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise StrictJSONError("JSON is not valid UTF-8") from exc
    elif isinstance(data, str):
        text = data
    else:
        raise StrictJSONError("JSON input must be text or bytes")
    _check_depth(text, max_depth)
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except StrictJSONError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise StrictJSONError("invalid JSON") from exc
