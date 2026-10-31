import re
import time

import pyotp
import pytest

from app import create_app, security
from app.db import get_db

H = {"X-Requested-With": "fetch"}
GOOD = "Str0ng!Pass"


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True, "DATABASE": str(tmp_path / "t.db"), "SECRET_KEY": "x", "DEV_MAILBOX": True,
        "MAX_FAILED_ATTEMPTS": 3, "LOCKOUT_SECONDS": 60,
        "ADMIN_EMAIL": "admin@example.com", "ADMIN_PASSWORD": "Admin!Pass1",
    })
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def post(c, url, **json):
    return c.post(url, json=json, headers=H)


def solve_captcha(app, c):
    """Підміняє очікувану відповідь у сесії (картинку ми не розпізнаємо)."""
    c.get("/api/captcha")
    with c.session_transaction() as s:
        s["captcha"] = security.hash_token("ABCDE")
    return "ABCDE"


def register(app, c, email="user@example.com", password=GOOD):
    return post(c, "/api/register", email=email, name="Test", password=password, captcha=solve_captcha(app, c))


def last_token(app, kind_path):
    with app.app_context():
        body = get_db().execute("SELECT body FROM outbox ORDER BY id DESC LIMIT 1").fetchone()["body"]
    return re.search(rf"#/{kind_path}/([\w-]+)", body).group(1)


def activate(app, c, email="user@example.com"):
    register(app, c, email)
    return post(c, "/api/activate", token=last_token(app, "activate"))


def login(c, email="user@example.com", password=GOOD):
    return post(c, "/api/login", email=email, password=password)


# ---- політика пароля ----
@pytest.mark.parametrize("pw", ["short1!A", "alllowercase1!", "ALLUPPERCASE1!", "NoDigits!!!", "NoSymbol123A", "Password1!"][1:])
def test_weak_passwords_rejected(app, client, pw):
    r = register(app, client, password=pw)
    assert r.status_code == 400 and r.json["problems"]


def test_short_password_rejected(app, client):
    assert register(app, client, password="Ab1!").status_code == 400


def test_password_hashed_with_argon2(app, client):
    register(app, client)
    with app.app_context():
        h = get_db().execute("SELECT password_hash FROM users WHERE email='user@example.com'").fetchone()[0]
    assert h.startswith("$argon2id$") and GOOD not in h


# ---- CAPTCHA ----
def test_register_requires_captcha(app, client):
    r = post(client, "/api/register", email="a@b.co", name="A", password=GOOD, captcha="WRONG")
    assert r.status_code == 400 and r.json["field"] == "captcha"


def test_captcha_is_one_time(app, client):
    solve_captcha(app, client)
    assert post(client, "/api/register", email="a@b.co", name="A", password=GOOD, captcha="ABCDE").status_code == 201
    assert post(client, "/api/register", email="c@b.co", name="A", password=GOOD, captcha="ABCDE").status_code == 400


# ---- активація ----
def test_cannot_login_before_activation_then_ok(app, client):
    register(app, client)
    r = login(client)
    assert r.status_code == 403 and r.json["code"] == "not_activated"
    assert post(client, "/api/activate", token=last_token(app, "activate")).status_code == 200
    assert login(client).json["status"] == "ok"
    assert client.get("/api/me").json["is_activated"] is True


def test_activation_token_one_time_and_expiring(app, client):
    register(app, client)
    tok = last_token(app, "activate")
    assert post(client, "/api/activate", token=tok).status_code == 200
    assert post(client, "/api/activate", token=tok).status_code == 400
    register(app, client, "second@example.com")
    tok2 = last_token(app, "activate")
    with app.app_context():
        db = get_db()
        db.execute("UPDATE tokens SET expires_at = ?", (int(time.time()) - 1,))
        db.commit()
    assert post(client, "/api/activate", token=tok2).status_code == 400


# ---- brute force ----
def test_bruteforce_lockout_and_log(app, client):
    activate(app, client)
    for _ in range(2):
        assert login(client, password="wrong").status_code == 401
    assert login(client, password="wrong").status_code == 429  # 3-тя спроба -> блокування
    assert login(client).status_code == 429  # навіть правильний пароль під час блокування
    admin = app.test_client()
    assert login(admin, "admin@example.com", "Admin!Pass1").json["status"] == "ok"
    logs = admin.get("/api/admin/logs?email=user@example.com").json
    results = [r["result"] for r in logs]
    assert results.count("fail") == 3 and "lockout" in results and "locked" in results
    summary = {r["email"]: r for r in admin.get("/api/admin/attempts").json}
    assert summary["user@example.com"]["failed"] == 3


def test_admin_unblock_resets_lock(app, client):
    activate(app, client)
    for _ in range(3):
        login(client, password="wrong")
    admin = app.test_client()
    login(admin, "admin@example.com", "Admin!Pass1")
    uid = next(u["id"] for u in admin.get("/api/admin/users").json if u["email"] == "user@example.com")
    assert admin.post(f"/api/admin/users/{uid}/unblock", headers=H).status_code == 200
    assert login(client).json["status"] == "ok"


def test_admin_block_user(app, client):
    activate(app, client)
    admin = app.test_client()
    login(admin, "admin@example.com", "Admin!Pass1")
    uid = next(u["id"] for u in admin.get("/api/admin/users").json if u["email"] == "user@example.com")
    admin.post(f"/api/admin/users/{uid}/block", headers=H)
    r = login(client)
    assert r.status_code == 403
    assert admin.post(f"/api/admin/users/{uid}/unblock", headers=H).status_code == 200
    assert login(client).status_code == 200


# ---- RBAC ----
def test_rbac(app, client):
    activate(app, client)
    assert client.get("/api/admin/users").status_code == 401
    login(client)
    assert client.get("/api/admin/users").status_code == 403
    assert client.get("/api/admin/logs").status_code == 403
    assert client.post("/api/admin/users/1/block", headers=H).status_code == 403


def test_csrf_header_required(app, client):
    assert client.post("/api/logout", json={}).status_code == 400


# ---- 2FA ----
def test_2fa_flow(app, client, monkeypatch):
    activate(app, client)
    login(client)
    secret = post(client, "/api/2fa/setup").json["secret"]
    assert post(client, "/api/2fa/enable", code="000000").status_code == 400
    assert post(client, "/api/2fa/enable", code=pyotp.TOTP(secret).now()).status_code == 200
    post(client, "/api/logout")

    assert login(client).json["status"] == "2fa_required"
    assert client.get("/api/me").status_code == 401  # ще не повністю автентифікований
    assert post(client, "/api/login/2fa", code="123456").status_code == 401
    # код з уже використаного кроку відхиляється (replay)
    totp = pyotp.TOTP(secret)
    code = totp.at(time.time() + 30)
    assert post(client, "/api/login/2fa", code=code).status_code == 200
    post(client, "/api/logout")
    login(client)
    assert post(client, "/api/login/2fa", code=code).status_code == 401

    # вимкнення 2FA (зсуваємо годинник на 2 кроки вперед, щоб коди були «свіжі»)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 90)
    c2 = app.test_client()
    login(c2)
    assert post(c2, "/api/login/2fa", code=totp.at(time.time())).status_code == 200
    monkeypatch.setattr(time, "time", lambda: real() + 150)
    assert post(c2, "/api/2fa/disable", password=GOOD, code=totp.at(time.time())).status_code == 200
    assert c2.get("/api/me").json["totp_enabled"] is False


# ---- відновлення пароля ----
def test_password_reset(app, client):
    activate(app, client)
    r = post(client, "/api/password/forgot", email="nobody@example.com")
    assert r.status_code == 200  # не розкриваємо існування акаунта
    post(client, "/api/password/forgot", email="user@example.com")
    tok = last_token(app, "reset")
    assert post(client, "/api/password/reset", token=tok, password="weak").status_code == 400
    assert post(client, "/api/password/reset", token=tok, password="N3w!Password").status_code == 200
    assert post(client, "/api/password/reset", token=tok, password="An0ther!Pass").status_code == 400  # одноразовий
    assert login(client).status_code == 401
    assert login(client, password="N3w!Password").status_code == 200


def test_reset_token_expires(app, client):
    activate(app, client)
    post(client, "/api/password/forgot", email="user@example.com")
    tok = last_token(app, "reset")
    with app.app_context():
        db = get_db()
        db.execute("UPDATE tokens SET expires_at = ?", (int(time.time()) - 1,))
        db.commit()
    assert post(client, "/api/password/reset", token=tok, password="N3w!Password").status_code == 400
