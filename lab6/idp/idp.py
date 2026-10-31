"""Демонстраційний OpenID Connect провайдер (authorization code flow, підписані RS256 id_token).

Потрібен лише для локальної демонстрації без реєстрації застосунку в Google/GitHub.
Основний застосунок використовує стандартний OIDC-клієнт (Authlib), тому для реального
провайдера достатньо змінити OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET.
"""
import html
import secrets
import time
from urllib.parse import urlencode

from authlib.jose import JsonWebKey, jwt
from flask import Flask, jsonify, redirect, request

ISSUER = "http://localhost:5001"
CLIENTS = {
    "lab6-client": {
        "secret": "lab6-secret",
        "redirect_uris": {"http://localhost:5000/api/oidc/callback"},
    }
}
ACCOUNTS = {
    "demo.user@idp.local": {"sub": "idp-1001", "name": "Олена Демо (OIDC)"},
    "ivan.petrenko@idp.local": {"sub": "idp-1002", "name": "Іван Петренко (OIDC)"},
}

app = Flask(__name__)
KEY = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "demo-key-1"})
codes: dict[str, dict] = {}
tokens: dict[str, dict] = {}


@app.get("/.well-known/openid-configuration")
def discovery():
    return jsonify({
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
    })


@app.get("/jwks")
def jwks():
    return jsonify({"keys": [KEY.as_dict(is_private=False)]})


PAGE = """<!doctype html><html lang="uk"><meta charset="utf-8"><title>Demo Identity Provider</title>
<style>body{{font-family:system-ui,sans-serif;background:#eef1f6;display:grid;place-items:center;min-height:100vh;margin:0}}
.card{{background:#fff;border-radius:14px;padding:32px;width:380px;box-shadow:0 8px 30px #0002}}
h1{{font-size:20px;margin:0 0 6px}}p{{color:#555;font-size:14px}}
button{{display:block;width:100%;text-align:left;margin-top:10px;padding:12px 14px;border:1px solid #cfd6e4;border-radius:10px;background:#fff;font-size:15px;cursor:pointer}}
button:hover{{background:#f1f5ff;border-color:#6b8cff}}small{{color:#777}}</style>
<div class="card"><h1>Demo Identity Provider</h1>
<p>Застосунок <b>{client}</b> запитує доступ до: <b>email, profile</b>. Оберіть обліковий запис:</p>
<form method="post">{hidden}{buttons}</form></div></html>"""


@app.route("/authorize", methods=["GET", "POST"])
def authorize():
    args = request.values
    client = CLIENTS.get(args.get("client_id", ""))
    if not client or args.get("redirect_uri") not in client["redirect_uris"] or args.get("response_type") != "code":
        return "invalid_request", 400
    if request.method == "GET":
        hidden = "".join(
            f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">' for k, v in args.items()
        )
        buttons = "".join(
            f'<button name="account" value="{html.escape(email)}">{html.escape(a["name"])}<br><small>{html.escape(email)}</small></button>'
            for email, a in ACCOUNTS.items()
        )
        return PAGE.format(client=html.escape(args["client_id"]), hidden=hidden, buttons=buttons)

    account = ACCOUNTS.get(request.form.get("account", ""))
    if not account:
        return "unknown account", 400
    code = secrets.token_urlsafe(24)
    codes[code] = {
        "email": request.form["account"], "account": account, "client_id": args["client_id"],
        "redirect_uri": args["redirect_uri"], "nonce": args.get("nonce"), "exp": time.time() + 120,
    }
    query = {"code": code, "state": args.get("state", "")}
    return redirect(f"{args['redirect_uri']}?{urlencode(query)}")


def _client_auth():
    cid = request.form.get("client_id") or (request.authorization.username if request.authorization else None)
    secret = request.form.get("client_secret") or (request.authorization.password if request.authorization else None)
    client = CLIENTS.get(cid or "")
    return cid if client and secrets.compare_digest(client["secret"], secret or "") else None


@app.post("/token")
def token():
    cid = _client_auth()
    data = codes.pop(request.form.get("code", ""), None)
    if not cid or not data or data["exp"] < time.time() or data["client_id"] != cid \
            or data["redirect_uri"] != request.form.get("redirect_uri"):
        return jsonify({"error": "invalid_grant"}), 400
    now = int(time.time())
    claims = {
        "iss": ISSUER, "sub": data["account"]["sub"], "aud": cid, "iat": now, "exp": now + 300,
        "email": data["email"], "email_verified": True, "name": data["account"]["name"],
    }
    if data["nonce"]:
        claims["nonce"] = data["nonce"]
    id_token = jwt.encode({"alg": "RS256", "kid": "demo-key-1"}, claims, KEY).decode()
    access = secrets.token_urlsafe(24)
    tokens[access] = claims
    return jsonify({"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": id_token})


@app.get("/userinfo")
def userinfo():
    auth = request.headers.get("Authorization", "")
    claims = tokens.get(auth.removeprefix("Bearer ").strip())
    if not claims:
        return jsonify({"error": "invalid_token"}), 401
    return jsonify({k: claims[k] for k in ("sub", "email", "email_verified", "name")})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
