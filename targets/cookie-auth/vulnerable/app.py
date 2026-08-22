"""cookie-auth target, vulnerable variant.

A deliberately different shape from header-auth: the token lives in a cookie,
the claims are uid/scope, and the endpoints are /profile and /staff. The token
handling is broken the same way: the signature is never verified and the scope
claim is trusted straight from the token.
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
COOKIE_NAME = "session"
DB_PATH = os.path.join(HERE, "users.db")


def read_token(cookie):
    if not cookie:
        return None
    try:
        return jwt.decode(cookie, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return None


app = Flask(__name__)


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    row = find_user(DB_PATH, data.get("username"), data.get("password"))
    if not row:
        return jsonify({"error": "invalid credentials"}), 401
    username, scope = row
    token = jwt.encode({"uid": username, "scope": scope}, SECRET, algorithm=ALGORITHM)
    resp = jsonify({"ok": True})
    resp.set_cookie(COOKIE_NAME, token)
    return resp


@app.get("/profile")
def profile():
    claims = read_token(request.cookies.get(COOKIE_NAME))
    if claims is None:
        return jsonify({"error": "missing or invalid token"}), 401
    return jsonify({"uid": claims.get("uid"), "scope": claims.get("scope")})


@app.get("/staff")
def staff():
    claims = read_token(request.cookies.get(COOKIE_NAME))
    if claims is None:
        return jsonify({"error": "missing or invalid token"}), 401
    if claims.get("scope") != "admin":
        return jsonify({"error": "staff only"}), 403
    return jsonify({"message": "welcome staff", "uid": claims.get("uid")})


if __name__ == "__main__":
    init_db(DB_PATH)
    app.run(host="127.0.0.1", port=5006)
