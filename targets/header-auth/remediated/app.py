"""header-auth target, remediated variant.

Same routes and users as the vulnerable variant. The difference is all in the
token handling: strong secret, pinned algorithm, full claim checks, and the
role comes from the database instead of the token.
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
from flask import Flask, jsonify, request

SECRET = "c8b1f0d4e2a67593bd4471aa90fe23c7d5e8091a6f2b3c4d5e6f708192a3b4c5d"
ALGORITHM = "HS256"
ISSUER = "header-auth"
AUDIENCE = "header-auth-clients"
TOKEN_TTL = timedelta(hours=1)
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

SEED_USERS = [
    ("alice", "password123", "user"),
    ("admin", "admin123", "admin"),
]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT, role TEXT)")
    conn.executemany("INSERT INTO users VALUES (?, ?, ?)", SEED_USERS)
    conn.commit()
    conn.close()


def find_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT username, role FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    conn.close()
    return row


def get_role(username):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT role FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row[0] if row else None


def read_token(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1]
    try:
        return jwt.decode(
            token,
            SECRET,
            algorithms=[ALGORITHM],
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
    row = find_user(data.get("username"), data.get("password"))
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
    token = jwt.encode(payload, SECRET, algorithm=ALGORITHM)
    return jsonify({"token": token})


@app.get("/me")
def me():
    claims = read_token(request.headers.get("Authorization"))
    if claims is None:
        return jsonify({"error": "missing or invalid token"}), 401
    role = get_role(claims["sub"])
    if role is None:
        return jsonify({"error": "unknown user"}), 401
    return jsonify({"sub": claims["sub"], "role": role})


@app.get("/admin")
def admin():
    claims = read_token(request.headers.get("Authorization"))
    if claims is None:
        return jsonify({"error": "missing or invalid token"}), 401
    role = get_role(claims["sub"])
    if role != "admin":
        return jsonify({"error": "admins only"}), 403
    return jsonify({"message": "welcome admin", "sub": claims["sub"]})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5002)
