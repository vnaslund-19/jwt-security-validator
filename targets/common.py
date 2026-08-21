"""Shared user store for the demo targets.

Every target uses the same users and lookups; they differ only in how they issue
and verify tokens. Each app passes its own database path.
"""

import sqlite3

SEED_USERS = [
    ("alice", "password123", "user"),
    ("admin", "admin123", "admin"),
]


def init_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT, role TEXT)")
    conn.executemany("INSERT INTO users VALUES (?, ?, ?)", SEED_USERS)
    conn.commit()
    conn.close()


def find_user(db_path, username, password):
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT username, role FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    conn.close()
    return row


def get_role(db_path, username):
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT role FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row[0] if row else None
