"""header-auth target, vulnerable variant.

Token goes in the Authorization header. The server issues an HS256 token with a
weak secret and then never checks it: no signature check, no claim validation,
and it trusts the role claim straight from the token.
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
        return jwt.decode(token, options={"verify_signature": False})
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
    app.run(host="127.0.0.1", port=5001)
