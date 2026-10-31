import hashlib
import hmac
import secrets
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Argon2id (RFC 9106): пам'яттєво-залежний хеш зі сіллю, що вбудована в рядок хешу.
_hasher = PasswordHasher()

COMMON_PASSWORDS = {
    "password", "password1", "password123", "qwerty123", "qwerty12345", "12345678",
    "123456789", "1234567890", "iloveyou1", "admin123", "welcome1", "letmein123",
    "p@ssw0rd", "p@ssword1", "passw0rd!", "qwerty1!", "abc12345", "zaq12wsx",
    "password1!", "welcome123", "qazwsx123", "1q2w3e4r", "1q2w3e4r5t",
}

# Хеш підставного паролю: вирівнює час відповіді для неіснуючих користувачів.
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Порівнює хеш введеного пароля з хешем у БД (Argon2 робить це у сталий час)."""
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and bool(password_hash)
    except (VerificationError, InvalidHashError):
        return False


def password_problems(password: str) -> list[str]:
    problems = []
    if len(password) < 8:
        problems.append("Довжина паролю повинна бути не менше 8 символів")
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
        problems.append("Пароль повинен містити великі і малі літери")
    if not any(c.isdigit() for c in password):
        problems.append("Пароль повинен містити цифру")
    if all(c.isalnum() for c in password):
        problems.append("Пароль повинен містити символ (не літеру і не цифру)")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("Цей пароль надто поширений")
    return problems


def password_strength(password: str) -> dict:
    """Оцінка 0..4 для індикатора сили пароля."""
    score = 0
    classes = [
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ]
    score += sum(classes)
    if len(password) >= 12:
        score += 1
    if len(password) < 8 or password.lower() in COMMON_PASSWORDS:
        score = min(score, 1)
    score = min(score, 4)
    labels = ["Дуже слабкий", "Слабкий", "Посередній", "Добрий", "Сильний"]
    return {"score": score, "label": labels[score], "problems": password_problems(password)}


# ---- одноразові токени (активація, відновлення) ----

def new_token() -> tuple[str, str]:
    """Повертає (токен для листа, його SHA-256 для БД). У БД сам токен не зберігається."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_token(raw)


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ---- TOTP ----

def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str, last_step: int) -> int | None:
    """Повертає номер кроку при успіху (захист від повторного використання коду), інакше None."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(secret)
    current = int(time.time()) // 30
    for step in (current - 1, current, current + 1):
        if step > last_step and hmac.compare_digest(totp.at(step * 30), code):
            return step
    return None
