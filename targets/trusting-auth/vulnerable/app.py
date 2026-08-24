"""trusting-auth target, vulnerable variant.

The "I verified the signature, so the token is trustworthy" mistake. It checks
the HMAC signature properly but with a weak secret, and then trusts every claim:
no exp/nbf/iss/aud checks, and the role and sub are taken straight from the
token. Tampering fails here (the signature is verified), so the only way in is
to crack the weak secret and sign a fresh token, which is what the checks do.
"""

import os
import sys

import jwt
from flask import Flask, jsonify, request

HERE = os.path.dirname(os.path.abspath(__file__))
# targets/ has no __init__, so put it on the path to import the shared user store
sys.path.insert(0, os.path.join(HERE, "..", ".."))
from common import find_user, init_db  # noqa: E402

SECRET = "secret"
ALGORITHM = "HS256"
DB_PATH = os.path.join(HERE, "users.db")


def read_token(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1]
    try:
        # verifies the signature but trusts the claims: no exp/nbf/iss/aud checks
        return jwt.decode(
            token,
            SECRET,
            algorithms=[ALGORITHM],
            options={"verify_exp": False, "verify_nbf": False, "verify_iss": False, "verify_aud": False},
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
    username, role = row
    token = jwt.encode({"sub": username, "role": role}, SECRET, algorithm=ALGORITHM)
    return jsonify({"token": token})


@app.get("/me")
def me():
    claims = read_token(request.headers.get("Authorization"))
    if claims is None:
        return jsonify({"error": "missing or invalid token"}), 401
    return jsonify({"sub": claims.get("sub"), "role": claims.get("role")})


@app.get("/admin")
def admin():
    claims = read_token(request.headers.get("Authorization"))
    if claims is None:
        return jsonify({"error": "missing or invalid token"}), 401
    if claims.get("role") != "admin":
        return jsonify({"error": "admins only"}), 403
    return jsonify({"message": "welcome admin", "sub": claims.get("sub")})


if __name__ == "__main__":
    init_db(DB_PATH)
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5005)))
