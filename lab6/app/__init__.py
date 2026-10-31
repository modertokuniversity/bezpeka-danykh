import os
import secrets
import time
from datetime import timedelta

import click
from authlib.integrations.flask_client import OAuth
from flask import Flask, send_from_directory

from . import security
from .db import close_db, get_db, init_db

oauth = OAuth()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder="static", static_url_path="/static", instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    env = os.environ.get
    app.config.update(
        APP_NAME="SecureAccounts",
        SECRET_KEY=env("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=env("DATABASE") or os.path.join(app.instance_path, "app.db"),
        BASE_URL=env("BASE_URL", "http://localhost:5000"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=env("COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        # brute force
        MAX_FAILED_ATTEMPTS=int(env("MAX_FAILED_ATTEMPTS", "5")),
        LOCKOUT_SECONDS=int(env("LOCKOUT_SECONDS", "300")),
        # терміни дії токенів (секунди)
        ACTIVATION_TTL=int(env("ACTIVATION_TTL", str(24 * 3600))),
        RESET_TTL=int(env("RESET_TTL", str(15 * 60))),
        # пошта
        SMTP_HOST=env("SMTP_HOST"),
        SMTP_PORT=int(env("SMTP_PORT", "587")),
        SMTP_USER=env("SMTP_USER"),
        SMTP_PASSWORD=env("SMTP_PASSWORD"),
        MAIL_FROM=env("MAIL_FROM", "no-reply@secure-accounts.local"),
        DEV_MAILBOX=env("DEV_MAILBOX", "0") == "1",
        # OpenID Connect (за замовчуванням — демо-провайдер з папки idp/; для Google:
        # OIDC_ISSUER=https://accounts.google.com + реальні client id/secret)
        OIDC_ISSUER=env("OIDC_ISSUER", "http://localhost:5001"),
        OIDC_CLIENT_ID=env("OIDC_CLIENT_ID", "lab6-client"),
        OIDC_CLIENT_SECRET=env("OIDC_CLIENT_SECRET", "lab6-secret"),
    )
    if test_config:
        app.config.update(test_config)

    oauth.init_app(app)
    issuer = app.config["OIDC_ISSUER"].rstrip("/")
    if "oidc" not in oauth._registry:
        oauth.register(
            "oidc",
            client_id=app.config["OIDC_CLIENT_ID"],
            client_secret=app.config["OIDC_CLIENT_SECRET"],
            server_metadata_url=f"{issuer}/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
        if env("ADMIN_PASSWORD") or app.config.get("ADMIN_PASSWORD"):
            ensure_admin(
                app.config.get("ADMIN_EMAIL") or env("ADMIN_EMAIL", "admin@example.com"),
                app.config.get("ADMIN_PASSWORD") or env("ADMIN_PASSWORD"),
            )

    from .api import bp
    app.register_blueprint(bp)

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'"
        )
        return resp

    @app.cli.command("create-admin")
    @click.argument("email")
    @click.password_option()
    def create_admin_cmd(email, password):
        problems = security.password_problems(password)
        if problems:
            raise click.ClickException("; ".join(problems))
        ensure_admin(email, password)
        click.echo(f"Адміністратор {email} створений/оновлений")

    return app


def ensure_admin(email: str, password: str) -> None:
    db = get_db()
    email = email.strip().lower()
    row = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if row is None:
        db.execute(
            "INSERT INTO users (email, name, password_hash, role, is_activated, created_at) "
            "VALUES (?, 'Administrator', ?, 'admin', 1, ?)",
            (email, security.hash_password(password), int(time.time())),
        )
        db.commit()
