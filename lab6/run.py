"""Запуск застосунку (порт 5000) і демо-OIDC провайдера (порт 5001) одним командою: python run.py"""
import os
import subprocess
import sys

os.environ.setdefault("DEV_MAILBOX", "1")  # листи доступні на сторінці «Dev-пошта» (замість реального SMTP)

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    idp = subprocess.Popen([sys.executable, os.path.join(here, "idp", "idp.py")])
    try:
        from app import create_app
        create_app().run(host="127.0.0.1", port=5000, debug=False)
    finally:
        idp.terminate()
