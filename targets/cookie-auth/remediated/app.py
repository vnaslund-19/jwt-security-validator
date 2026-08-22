"""cookie-auth target, remediated variant.

Same shape as the vulnerable variant (cookie token, uid/scope, /profile /staff)
but with proper token handling: strong secret, pinned algorithm, full claim
checks, and the scope comes from the database instead of the token.
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

SECRET = "a3f5c9d18b6e2470af8c1d59e30b7246c5a9f812b4e6708192a3b4c5d6e7f809"
ALGORITHM = "HS256"
ISSUER = "cookie-auth"
AUDIENCE = "cookie-auth-clients"
TOKEN_TTL = timedelta(hours=1)
COOKIE_NAME = "session"
DB_PATH = os.path.join(HERE, "users.db")


def read_token(cookie):
    if not cookie:
        return None
    try:
        return jwt.decode(
            cookie,
            SECRET,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["exp", "nbf", "iss", "aud", "uid"]},
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
        "uid": username,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_TTL,
    }
    token = jwt.encode(payload, SECRET, algorithm=ALGORITHM)
    resp = jsonify({"ok": True})
    resp.set_cookie(COOKIE_NAME, token)
    return resp


@app.get("/profile")
def profile():
    claims = read_token(request.cookies.get(COOKIE_NAME))
    if claims is None:
        return jsonify({"error": "missing or invalid token"}), 401
    scope = get_role(DB_PATH, claims["uid"])
    if scope is None:
        return jsonify({"error": "unknown user"}), 401
    return jsonify({"uid": claims["uid"], "scope": scope})


@app.get("/staff")
def staff():
    claims = read_token(request.cookies.get(COOKIE_NAME))
    if claims is None:
        return jsonify({"error": "missing or invalid token"}), 401
    scope = get_role(DB_PATH, claims["uid"])
    if scope != "admin":
        return jsonify({"error": "staff only"}), 403
    return jsonify({"message": "welcome staff", "uid": claims["uid"]})


if __name__ == "__main__":
    init_db(DB_PATH)
    app.run(host="127.0.0.1", port=5007)
