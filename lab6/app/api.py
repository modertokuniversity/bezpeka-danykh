import base64
import hmac
import io
import re
import secrets
import time
from functools import wraps

import qrcode
import pyotp
from flask import Blueprint, Response, current_app, jsonify, redirect, request, session, url_for

from . import captcha, security
from .db import get_db
from .mailer import send_mail

bp = Blueprint("api", __name__, url_prefix="/api")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
GENERIC_LOGIN_ERROR = "Невірний email або пароль"
PRE_2FA_TTL = 300


# ---------------------------------------------------------------- helpers

def now() -> int:
    return int(time.time())


def err(message: str, status: int = 400, **extra):
    return jsonify({"error": message, **extra}), status


def body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def client_ip() -> str:
    return request.remote_addr or "unknown"


def log_attempt(email: str, user_id, result: str, detail: str = "") -> None:
    db = get_db()
    db.execute(
        "INSERT INTO login_log (ts, email, user_id, ip, result, detail) VALUES (?, ?, ?, ?, ?, ?)",
        (now(), email[:254], user_id, client_ip(), result, detail),
    )
    db.commit()


def user_by_id(uid):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def user_by_email(email: str):
    return get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def public_user(u) -> dict:
    return {
        "id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"],
        "is_activated": bool(u["is_activated"]), "is_blocked": bool(u["is_blocked"]),
        "totp_enabled": bool(u["totp_enabled"]), "oidc": bool(u["oidc_sub"]),
        "created_at": u["created_at"],
    }


def current_user():
    uid = session.get("uid")
    if uid is None:
        return None
    u = user_by_id(uid)
    if u is None or u["is_blocked"]:
        session.clear()
        return None
    return u


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if u is None:
            return err("Потрібна автентифікація", 401)
        return fn(u, *a, **kw)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if u is None:
            return err("Потрібна автентифікація", 401)
        if u["role"] != "admin":
            return err("Недостатньо прав", 403)
        return fn(u, *a, **kw)
    return wrapper


def start_session(u) -> None:
    session.clear()  # проти session fixation
    session["uid"] = u["id"]
    session.permanent = True


def issue_token(user_id: int, kind: str, ttl: int) -> str:
    raw, digest = security.new_token()
    db = get_db()
    db.execute("UPDATE tokens SET used = 1 WHERE user_id = ? AND kind = ? AND used = 0", (user_id, kind))
    db.execute(
        "INSERT INTO tokens (user_id, kind, token_hash, expires_at) VALUES (?, ?, ?, ?)",
        (user_id, kind, digest, now() + ttl),
    )
    db.commit()
    return raw


def consume_token(raw: str, kind: str):
    """Повертає рядок користувача, якщо токен чинний; токен гаситься (одноразовий)."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM tokens WHERE token_hash = ? AND kind = ?", (security.hash_token(raw or ""), kind)
    ).fetchone()
    if row is None or row["used"] or row["expires_at"] < now():
        return None
    db.execute("UPDATE tokens SET used = 1 WHERE id = ?", (row["id"],))
    db.commit()
    return user_by_id(row["user_id"])


def send_activation(u) -> None:
    ttl = current_app.config["ACTIVATION_TTL"]
    token = issue_token(u["id"], "activate", ttl)
    link = f"{current_app.config['BASE_URL']}/#/activate/{token}"
    send_mail(
        u["email"], "Активація облікового запису",
        f"Вітаємо, {u['name']}!\n\nЩоб активувати обліковий запис, перейдіть за посиланням:\n{link}\n\n"
        f"Посилання одноразове і діє {ttl // 60} хв. Якщо ви не реєструвалися — проігноруйте цей лист.",
    )


_rate: dict[tuple, list[int]] = {}


def rate_limited(bucket: str, limit: int, window: int) -> bool:
    key = (bucket, client_ip())
    hits = [t for t in _rate.get(key, []) if t > now() - window]
    if len(hits) >= limit:
        _rate[key] = hits
        return True
    hits.append(now())
    _rate[key] = hits
    return False


# ---------------------------------------------------------------- захист запитів

@bp.before_request
def require_xhr_header():
    # Кастомний заголовок неможливо виставити з чужого origin без CORS preflight -> захист від CSRF.
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.headers.get("X-Requested-With") != "fetch":
        return err("Відсутній заголовок X-Requested-With", 400)


# ---------------------------------------------------------------- публічні

@bp.get("/captcha")
def get_captcha():
    text = captcha.new_text()
    session["captcha"] = security.hash_token(text)
    session["captcha_ts"] = now()
    resp = Response(captcha.render(text), mimetype="image/png")
    resp.headers["Cache-Control"] = "no-store"
    return resp


def check_captcha(answer: str) -> bool:
    expected = session.pop("captcha", None)  # одноразова
    ts = session.pop("captcha_ts", 0)
    if not expected or now() - ts > 300:
        return False
    return hmac.compare_digest(expected, security.hash_token((answer or "").strip().upper()))


@bp.post("/password-strength")
def password_strength():
    return jsonify(security.password_strength(str(body().get("password", ""))))


@bp.post("/register")
def register():
    data = body()
    email = str(data.get("email", "")).strip().lower()
    name = str(data.get("name", "")).strip()
    password = str(data.get("password", ""))

    if not check_captcha(str(data.get("captcha", ""))):
        return err("Невірна CAPTCHA", 400, field="captcha")
    if not EMAIL_RE.match(email) or len(email) > 254:
        return err("Некоректний email", 400, field="email")
    if not 1 <= len(name) <= 80:
        return err("Вкажіть ім'я (до 80 символів)", 400, field="name")
    problems = security.password_problems(password)
    if problems:
        return err("Пароль не відповідає політиці безпеки", 400, field="password", problems=problems)

    if user_by_email(email) is not None:
        # не розкриваємо, що email зайнятий: відповідь та сама, що й при успіху
        return jsonify({"ok": True, "message": "Перевірте пошту для активації облікового запису"}), 201

    db = get_db()
    cur = db.execute(
        "INSERT INTO users (email, name, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (email, name, security.hash_password(password), now()),
    )
    db.commit()
    send_activation(user_by_id(cur.lastrowid))
    return jsonify({"ok": True, "message": "Перевірте пошту для активації облікового запису"}), 201


@bp.post("/activate")
def activate():
    u = consume_token(str(body().get("token", "")), "activate")
    if u is None:
        return err("Посилання недійсне або термін його дії минув", 400)
    db = get_db()
    db.execute("UPDATE users SET is_activated = 1 WHERE id = ?", (u["id"],))
    db.commit()
    return jsonify({"ok": True, "message": "Обліковий запис активовано. Тепер можна увійти."})


@bp.post("/activate/resend")
def activate_resend():
    if rate_limited("resend", 5, 600):
        return err("Забагато запитів, спробуйте пізніше", 429)
    u = user_by_email(str(body().get("email", "")).strip().lower())
    if u is not None and not u["is_activated"]:
        send_activation(u)
    return jsonify({"ok": True, "message": "Якщо обліковий запис існує і не активований — лист надіслано"})


# ---------------------------------------------------------------- вхід / вихід

@bp.post("/login")
def login():
    data = body()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    cfg = current_app.config
    u = user_by_email(email)

    if u is None:
        security.verify_password(None, password)  # вирівнюємо час відповіді
        log_attempt(email, None, "fail", "unknown_user")
        return err(GENERIC_LOGIN_ERROR, 401)

    if u["locked_until"] > now():
        wait = u["locked_until"] - now()
        log_attempt(email, u["id"], "locked", "attempt_during_lock")
        return err(f"Обліковий запис тимчасово заблоковано через забагато невдалих спроб. Спробуйте через {wait} с.",
                   429, retry_after=wait)

    if not security.verify_password(u["password_hash"], password):
        register_failure(u, "bad_password")
        return fail_response(u)

    if u["is_blocked"]:
        log_attempt(email, u["id"], "blocked", "blocked_by_admin")
        return err("Обліковий запис заблоковано адміністратором", 403)
    if not u["is_activated"]:
        log_attempt(email, u["id"], "not_activated")
        return err("Обліковий запис не активовано. Перейдіть за посиланням з листа.", 403, code="not_activated")

    if u["totp_enabled"]:
        session.clear()
        session["pre_2fa"] = u["id"]
        session["pre_2fa_ts"] = now()
        log_attempt(email, u["id"], "password_ok", "2fa_required")
        return jsonify({"status": "2fa_required"})

    finish_login(u)
    return jsonify({"status": "ok", "user": public_user(u)})


def register_failure(u, detail: str) -> None:
    cfg = current_app.config
    db = get_db()
    attempts = u["failed_attempts"] + 1
    if attempts >= cfg["MAX_FAILED_ATTEMPTS"]:
        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
            (now() + cfg["LOCKOUT_SECONDS"], u["id"]),
        )
        log_attempt(u["email"], u["id"], "fail", detail)
        log_attempt(u["email"], u["id"], "lockout", f"locked_for_{cfg['LOCKOUT_SECONDS']}s")
    else:
        db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, u["id"]))
        log_attempt(u["email"], u["id"], "fail", detail)
    db.commit()


def fail_response(u):
    fresh = user_by_id(u["id"])
    if fresh["locked_until"] > now():
        wait = fresh["locked_until"] - now()
        return err(f"Забагато невдалих спроб. Обліковий запис заблоковано на {wait} с.", 429, retry_after=wait)
    return err(GENERIC_LOGIN_ERROR, 401)


def finish_login(u, detail: str = "password") -> None:
    db = get_db()
    db.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?", (u["id"],))
    db.commit()
    start_session(u)
    log_attempt(u["email"], u["id"], "success", detail)


@bp.post("/login/2fa")
def login_2fa():
    uid = session.get("pre_2fa")
    if uid is None or now() - session.get("pre_2fa_ts", 0) > PRE_2FA_TTL:
        session.clear()
        return err("Сесія входу завершилась, увійдіть знову", 401)
    u = user_by_id(uid)
    if u["locked_until"] > now():
        return err("Обліковий запис тимчасово заблоковано", 429)
    step = security.verify_totp(u["totp_secret"], str(body().get("code", "")), u["totp_last_step"])
    if step is None:
        register_failure(u, "bad_2fa_code")
        if user_by_id(uid)["locked_until"] > now():
            session.clear()
        return err("Невірний код 2FA", 401)
    db = get_db()
    db.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, u["id"]))
    db.commit()
    finish_login(u, "password+2fa")
    return jsonify({"status": "ok", "user": public_user(user_by_id(uid))})


@bp.post("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@bp.get("/me")
@login_required
def me(u):
    return jsonify(public_user(u))


# ---------------------------------------------------------------- 2FA (TOTP)

def qr_data_uri(text: str) -> str:
    buf = io.BytesIO()
    qrcode.make(text, box_size=6, border=2).save(buf, "PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


@bp.post("/2fa/setup")
@login_required
def twofa_setup(u):
    if u["totp_enabled"]:
        return err("2FA вже увімкнено", 400)
    secret = security.new_totp_secret()
    session["totp_pending"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=u["email"], issuer_name=current_app.config["APP_NAME"])
    return jsonify({"secret": secret, "qr": qr_data_uri(uri)})


@bp.post("/2fa/enable")
@login_required
def twofa_enable(u):
    secret = session.get("totp_pending")
    if not secret:
        return err("Спочатку почніть налаштування 2FA", 400)
    step = security.verify_totp(secret, str(body().get("code", "")), 0)
    if step is None:
        return err("Невірний код, спробуйте ще раз", 400)
    db = get_db()
    db.execute(
        "UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_last_step = ? WHERE id = ?",
        (secret, step, u["id"]),
    )
    db.commit()
    session.pop("totp_pending", None)
    return jsonify({"ok": True})


@bp.post("/2fa/disable")
@login_required
def twofa_disable(u):
    data = body()
    if not u["totp_enabled"]:
        return err("2FA не увімкнено", 400)
    if not security.verify_password(u["password_hash"], str(data.get("password", ""))):
        return err("Невірний пароль", 400)
    step = security.verify_totp(u["totp_secret"], str(data.get("code", "")), u["totp_last_step"])
    if step is None:
        return err("Невірний код 2FA", 400)
    db = get_db()
    db.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = 0 WHERE id = ?", (u["id"],))
    db.commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------- відновлення пароля

@bp.post("/password/forgot")
def password_forgot():
    if rate_limited("forgot", 5, 600):
        return err("Забагато запитів, спробуйте пізніше", 429)
    u = user_by_email(str(body().get("email", "")).strip().lower())
    if u is not None and not u["is_blocked"]:
        ttl = current_app.config["RESET_TTL"]
        token = issue_token(u["id"], "reset", ttl)
        link = f"{current_app.config['BASE_URL']}/#/reset/{token}"
        send_mail(
            u["email"], "Відновлення пароля",
            f"Ми отримали запит на відновлення пароля.\n\nЩоб встановити новий пароль, перейдіть за посиланням:\n{link}\n\n"
            f"Посилання одноразове і діє {ttl // 60} хв. Якщо ви не робили цього запиту — проігноруйте лист.",
        )
    return jsonify({"ok": True, "message": "Якщо такий обліковий запис існує, ми надіслали лист з інструкціями"})


@bp.post("/password/reset")
def password_reset():
    data = body()
    password = str(data.get("password", ""))
    problems = security.password_problems(password)
    if problems:
        return err("Пароль не відповідає політиці безпеки", 400, field="password", problems=problems)
    u = consume_token(str(data.get("token", "")), "reset")
    if u is None:
        return err("Посилання недійсне або термін його дії минув", 400)
    db = get_db()
    db.execute(
        "UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = 0 WHERE id = ?",
        (security.hash_password(password), u["id"]),
    )
    db.commit()
    log_attempt(u["email"], u["id"], "password_reset")
    return jsonify({"ok": True, "message": "Пароль змінено. Тепер можна увійти."})


# ---------------------------------------------------------------- OpenID Connect

@bp.get("/oidc/login")
def oidc_login():
    from . import oauth
    redirect_uri = url_for("api.oidc_callback", _external=True)
    return oauth.oidc.authorize_redirect(redirect_uri)


@bp.get("/oidc/callback")
def oidc_callback():
    from . import oauth
    base = current_app.config["BASE_URL"]
    try:
        token = oauth.oidc.authorize_access_token()
        info = token.get("userinfo") or oauth.oidc.userinfo()
    except Exception:  # помилка провайдера / невалідний state чи nonce
        current_app.logger.exception("OIDC error")
        log_attempt("(oidc)", None, "fail", "oidc_error")
        return redirect(f"{base}/#/login?error=oidc")

    email = str(info.get("email", "")).lower()
    sub = f"{current_app.config['OIDC_ISSUER']}|{info.get('sub')}"
    if not email or not info.get("email_verified", False):
        log_attempt(email or "(oidc)", None, "fail", "oidc_email_not_verified")
        return redirect(f"{base}/#/login?error=oidc_email")

    db = get_db()
    u = db.execute("SELECT * FROM users WHERE oidc_sub = ?", (sub,)).fetchone() or user_by_email(email)
    if u is None:
        cur = db.execute(
            "INSERT INTO users (email, name, password_hash, is_activated, oidc_sub, created_at) VALUES (?, ?, ?, 1, ?, ?)",
            (email, str(info.get("name") or email.split("@")[0])[:80],
             security.hash_password(secrets.token_urlsafe(32)), sub, now()),
        )
        db.commit()
        u = user_by_id(cur.lastrowid)
    else:
        # IdP підтвердив email -> акаунт вважаємо активованим і прив'язуємо sub
        db.execute("UPDATE users SET oidc_sub = COALESCE(oidc_sub, ?), is_activated = 1 WHERE id = ?", (sub, u["id"]))
        db.commit()
        u = user_by_id(u["id"])

    if u["is_blocked"]:
        log_attempt(email, u["id"], "blocked", "blocked_by_admin (oidc)")
        return redirect(f"{base}/#/login?error=blocked")
    finish_login(u, "oidc")
    return redirect(f"{base}/#/profile")


# ---------------------------------------------------------------- адміністратор (RBAC)

@bp.get("/admin/users")
@admin_required
def admin_users(_admin):
    rows = get_db().execute("SELECT * FROM users ORDER BY id").fetchall()
    out = []
    for r in rows:
        d = public_user(r)
        d["locked_until"] = r["locked_until"] if r["locked_until"] > now() else 0
        d["failed_attempts"] = r["failed_attempts"]
        out.append(d)
    return jsonify(out)


def set_blocked(admin, uid: int, blocked: bool):
    u = user_by_id(uid)
    if u is None:
        return err("Користувача не знайдено", 404)
    if u["id"] == admin["id"]:
        return err("Не можна змінити статус власного облікового запису", 400)
    db = get_db()
    # при розблокуванні скидаємо і тимчасове блокування від brute force
    db.execute(
        "UPDATE users SET is_blocked = ?, failed_attempts = 0, locked_until = 0 WHERE id = ?", (int(blocked), uid)
    )
    db.commit()
    log_attempt(u["email"], uid, "admin_block" if blocked else "admin_unblock", f"by {admin['email']}")
    return jsonify(public_user(user_by_id(uid)))


@bp.post("/admin/users/<int:uid>/block")
@admin_required
def admin_block(admin, uid):
    return set_blocked(admin, uid, True)


@bp.post("/admin/users/<int:uid>/unblock")
@admin_required
def admin_unblock(admin, uid):
    return set_blocked(admin, uid, False)


@bp.get("/admin/logs")
@admin_required
def admin_logs(_admin):
    email = request.args.get("email", "").strip().lower()
    result = request.args.get("result", "").strip()
    sql, args = "SELECT * FROM login_log WHERE 1=1", []
    if email:
        sql += " AND email LIKE ?"
        args.append(f"%{email}%")
    if result:
        sql += " AND result = ?"
        args.append(result)
    sql += " ORDER BY id DESC LIMIT 300"
    rows = get_db().execute(sql, args).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.get("/admin/attempts")
@admin_required
def admin_attempts(_admin):
    """Зведення: хто і скільки разів намагався увійти (невдалі / успішні спроби)."""
    rows = get_db().execute(
        """SELECT email,
                  SUM(result = 'fail') AS failed,
                  SUM(result = 'success') AS success,
                  SUM(result = 'lockout') AS lockouts,
                  MAX(ts) AS last_ts
           FROM login_log
           WHERE result IN ('fail', 'success', 'lockout', 'locked')
           GROUP BY email ORDER BY failed DESC, last_ts DESC"""
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------- dev-пошта

@bp.get("/dev/mailbox")
def dev_mailbox():
    if not current_app.config["DEV_MAILBOX"]:
        return err("Not found", 404)
    to = request.args.get("to", "").strip().lower()
    sql, args = "SELECT * FROM outbox", []
    if to:
        sql += " WHERE to_addr = ?"
        args.append(to)
    rows = get_db().execute(sql + " ORDER BY id DESC LIMIT 50", args).fetchall()
    return jsonify([dict(r) for r in rows])
