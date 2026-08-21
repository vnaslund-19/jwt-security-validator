"""rsa-auth target, vulnerable variant.

Signs tokens with RS256. The flaw is that it trusts the token's alg: an RS256
token is checked with the RSA public key, but an HS256 token is checked with
HMAC using that same public key. The public key is public, so anyone can forge
an HS256 token the server accepts. Everything else about the app is sound.

The private key stays in memory. The public key is written next to this file so
the checker can read it, the way an attacker would obtain a published key.
"""

import base64
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

HERE = os.path.dirname(os.path.abspath(__file__))
# targets/ has no __init__, so put it on the path to import the shared user store
sys.path.insert(0, os.path.join(HERE, "..", ".."))
from common import find_user, get_role, init_db  # noqa: E402

ISSUER = "rsa-auth"
AUDIENCE = "rsa-auth-clients"
TOKEN_TTL = timedelta(hours=1)
DB_PATH = os.path.join(HERE, "users.db")
PUBLIC_KEY_PATH = os.path.join(HERE, "public_key.pem")

PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_PEM = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)


def read_token(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1]
    claims = _verify_signature(token)
    if claims is None:
        return None
    return _check_claims(claims)


def _verify_signature(token):
    try:
        alg = jwt.get_unverified_header(token).get("alg")
    except jwt.InvalidTokenError:
        return None
    if alg == "RS256":
        try:
            return jwt.decode(
                token,
                PUBLIC_PEM,
                algorithms=["RS256"],
                options={"verify_exp": False, "verify_nbf": False, "verify_iss": False, "verify_aud": False},
            )
        except jwt.InvalidTokenError:
            return None
    if alg == "HS256":
        return _verify_hs256_with_public_key(token)
    return None


def _verify_hs256_with_public_key(token):
    header_b64, payload_b64, sig_b64 = token.split(".")
    signature = hmac.new(PUBLIC_PEM, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(sig_b64, base64.urlsafe_b64encode(signature).rstrip(b"=").decode()):
        return None
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _check_claims(claims):
    now = datetime.now(timezone.utc).timestamp()
    if claims.get("iss") != ISSUER or claims.get("aud") != AUDIENCE:
        return None
    if "exp" not in claims or claims["exp"] < now:
        return None
    if "nbf" not in claims or claims["nbf"] > now:
        return None
    if "sub" not in claims:
        return None
    return claims


app = Flask(__name__)


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    row = find_user(DB_PATH, data.get("username"), data.get("password"))
    if not row:
        return jsonify({"error": "invalid credentials"}), 401
    username, _ = row
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_TTL,
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return jsonify({"token": token})


@app.get("/me")
def me():
    claims = read_token(request.headers.get("Authorization"))
    if claims is None:
        return jsonify({"error": "missing or invalid token"}), 401
    role = get_role(DB_PATH, claims["sub"])
    if role is None:
        return jsonify({"error": "unknown user"}), 401
    return jsonify({"sub": claims["sub"], "role": role})


@app.get("/admin")
def admin():
    claims = read_token(request.headers.get("Authorization"))
    if claims is None:
        return jsonify({"error": "missing or invalid token"}), 401
    role = get_role(DB_PATH, claims["sub"])
    if role != "admin":
        return jsonify({"error": "admins only"}), 403
    return jsonify({"message": "welcome admin", "sub": claims["sub"]})


if __name__ == "__main__":
    init_db(DB_PATH)
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(PUBLIC_PEM)
    app.run(host="127.0.0.1", port=5003)
