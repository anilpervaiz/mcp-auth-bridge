"""A tiny, loopback-only local issuer for the demo; never use in production."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwk

KEY_FILE = Path(".demo/demo-private.pem")
ISSUER = "http://127.0.0.1:8180/issuer"


def ensure_key() -> dict[str, object]:
    KEY_FILE.parent.mkdir(mode=0o700, exist_ok=True)
    if KEY_FILE.exists():
        pem = KEY_FILE.read_bytes()
    else:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        KEY_FILE.write_bytes(pem)
        KEY_FILE.chmod(0o600)
    private_key = serialization.load_pem_private_key(pem, password=None)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_jwk = jwk.import_key(
        public_pem, "RSA", parameters={"kid": "demo-key-1", "use": "sig", "alg": "RS256"}
    ).as_dict()
    public_jwk.pop("kid", None)
    public_jwk.update({"kid": "demo-key-1", "use": "sig", "alg": "RS256"})
    result: dict[str, object] = dict(public_jwk)
    return result


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/.well-known/jwks")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/.well-known/oauth-authorization-server/issuer":
            body = json.dumps(
                {"issuer": ISSUER, "jwks_uri": "http://127.0.0.1:8180/.well-known/jwks"}
            ).encode()
        elif self.path == "/.well-known/jwks":
            body = json.dumps({"keys": [ensure_key()]}).encode()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        print("demo issuer: " + fmt % args)


def main() -> None:
    if os.getenv("MAB_DEMO_CONFIRM_LOOPBACK") != "yes":
        raise SystemExit("demo issuer requires MAB_DEMO_CONFIRM_LOOPBACK=yes")
    try:
        ThreadingHTTPServer(("127.0.0.1", 8180), Handler).serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
