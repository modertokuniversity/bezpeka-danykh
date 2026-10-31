import smtplib
import time
from email.message import EmailMessage

from flask import current_app

from .db import get_db


def send_mail(to_addr: str, subject: str, body: str) -> None:
    """Кладе лист у таблицю outbox (dev-поштова скринька) і, якщо налаштовано SMTP, відправляє його."""
    db = get_db()
    db.execute(
        "INSERT INTO outbox (ts, to_addr, subject, body) VALUES (?, ?, ?, ?)",
        (int(time.time()), to_addr, subject, body),
    )
    db.commit()

    cfg = current_app.config
    if not cfg.get("SMTP_HOST"):
        return
    msg = EmailMessage()
    msg["From"] = cfg["MAIL_FROM"]
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10) as smtp:
            if cfg.get("SMTP_USER"):
                smtp.starttls()
                smtp.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
            smtp.send_message(msg)
    except OSError:
        current_app.logger.exception("SMTP: не вдалося відправити лист")
