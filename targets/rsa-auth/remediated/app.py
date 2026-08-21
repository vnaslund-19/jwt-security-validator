"""rsa-auth target, remediated variant.

Same as the vulnerable variant but the algorithm is pinned to RS256, so an
HS256 token forged with the public key is rejected outright.

The private key stays in memory. The public key is written next to this file so
the checker can read it, the way an attacker would obtain a published key.
"""

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
    try:
        return jwt.decode(
            token,
            PUBLIC_PEM,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["exp", "nbf", "iss", "aud", "sub"]},
        )
    except jwt.InvalidTokenError:
        return None


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
    app.run(host="127.0.0.1", port=5004)
