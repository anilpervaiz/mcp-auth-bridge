"""Mint local-only test tokens. Never publish or reuse this demo signing key."""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from joserfc import jwk, jwt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", nargs="*", default=["mcp:use"])
    parser.add_argument("--audience", default="http://127.0.0.1:8080/mcp")
    parser.add_argument("--issuer", default="http://127.0.0.1:8180/issuer")
    parser.add_argument("--expires-in", type=int, default=300)
    args = parser.parse_args()
    pem = Path(".demo/demo-private.pem").read_bytes()
    key = jwk.import_key(pem, "RSA")
    now = int(time.time())
    token = jwt.encode(
        {"alg": "RS256", "kid": "demo-key-1", "typ": "at+jwt"},
        {
            "iss": args.issuer,
            "sub": "local-demo-user",
            "client_id": "local-demo-client",
            "aud": args.audience,
            "iat": now,
            "exp": now + args.expires_in,
            "scope": " ".join(args.scope),
        },
        key,
        algorithms=["RS256"],
    )
    print(token)


if __name__ == "__main__":
    main()
