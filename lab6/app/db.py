import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    is_activated    INTEGER NOT NULL DEFAULT 0,
    is_blocked      INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0,
    totp_secret     TEXT,
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    totp_last_step  INTEGER NOT NULL DEFAULT 0,
    oidc_sub        TEXT UNIQUE,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('activate', 'reset')),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    email   TEXT NOT NULL,
    user_id INTEGER,
    ip      TEXT NOT NULL,
    result  TEXT NOT NULL,
    detail  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_log_email ON login_log(email);

CREATE TABLE IF NOT EXISTS outbox (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    to_addr TEXT NOT NULL,
    subject TEXT NOT NULL,
    body    TEXT NOT NULL
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()
