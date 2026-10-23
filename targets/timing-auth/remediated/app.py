"""timing-auth target, remediated variant.

Same as the vulnerable variant but enforces exp and nbf, so a token past its exp
or used before its nbf is rejected. Tokens expire a few seconds after login to
keep the tests fast.
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import jwt
from flask import Flask, jsonify, request

HERE = os.path.dirname(os.path.abspath(__file__))
# targets/ has no __init__, so put it on the path to import the shared user store
sys.path.insert(0, os.path.join(HERE, "..", ".."))
from common import find_user, get_role, init_db  # noqa: E402

SECRET = "c8b1f0d4e2a67593bd4471aa90fe23c7d5e8091a6f2b3c4d5e6f708192a3b4c5d"
ALGORITHM = "HS256"
NBF_DELAY = timedelta(seconds=2)
TOKEN_TTL = timedelta(seconds=5)
DB_PATH = os.path.join(HERE, "users.db")


def read_token(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    try:
        # verifies the signature and enforces exp and nbf, so a token past its
        # exp or used before its nbf is rejected
        return jwt.decode(
            auth_header.split(" ", 1)[1],
            SECRET,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "nbf"]},
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
    payload = {"sub": username, "iat": now, "nbf": now + NBF_DELAY, "exp": now + TOKEN_TTL}
    token = jwt.encode(payload, SECRET, algorithm=ALGORITHM)
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
    if get_role(DB_PATH, claims["sub"]) != "admin":
        return jsonify({"error": "admins only"}), 403
    return jsonify({"message": "welcome admin", "sub": claims["sub"]})


if __name__ == "__main__":
    init_db(DB_PATH)
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5009)))
