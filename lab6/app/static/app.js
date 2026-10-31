"use strict";

// ---------- допоміжні функції ----------
const $app = document.getElementById("app");
const $nav = document.getElementById("nav");
let me = null;

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c != null && c !== false) el.append(c.nodeType ? c : document.createTextNode(c));
  return el;
}

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch("/api" + path, {
    method,
    headers: { "X-Requested-With": "fetch", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* не JSON */ }
  if (!res.ok) throw Object.assign(new Error(data.error || "Помилка запиту"), { status: res.status, data });
  return data;
}

function alertBox(kind, text, list) {
  return h("div", { class: "alert " + kind }, text, list && list.length ? h("ul", {}, list.map(p => h("li", {}, p))) : null);
}
function showMsg(box, kind, text, list) { box.replaceChildren(alertBox(kind, text, list)); }

const fmt = ts => ts ? new Date(ts * 1000).toLocaleString("uk-UA") : "—";
const go = hash => { location.hash = hash; };

function field(label, input) { return h("div", {}, h("label", {}, label), input); }

function render(...nodes) { $app.replaceChildren(...nodes); window.scrollTo(0, 0); }

// ---------- індикатор сили пароля ----------
function passwordField(labelText = "Пароль", onInfo) {
  const input = h("input", { type: "password", autocomplete: "new-password", required: true });
  const meter = h("div", { class: "meter" }, h("span"), h("span"), h("span"), h("span"));
  const meterLabel = h("div", { class: "meter-label" }, "Введіть пароль");
  const checks = h("ul", { class: "checks" });
  const rules = [
    ["Щонайменше 8 символів", p => p.length >= 8],
    ["Великі та малі літери", p => /[a-zа-яіїєґ]/.test(p) && /[A-ZА-ЯІЇЄҐ]/.test(p)],
    ["Цифра", p => /\d/.test(p)],
    ["Символ (не літера і не цифра)", p => /[^\p{L}\d]/u.test(p)],
  ];
  const items = rules.map(([t]) => h("li", {}, t));
  checks.append(...items);
  let timer;
  input.addEventListener("input", () => {
    const p = input.value;
    rules.forEach(([, f], i) => items[i].classList.toggle("pass", f(p)));
    clearTimeout(timer);
    timer = setTimeout(async () => {
      if (!p) { meter.className = "meter"; meterLabel.textContent = "Введіть пароль"; return; }
      try {
        const r = await api("/password-strength", { method: "POST", body: { password: p } });
        meter.className = "meter s" + Math.max(r.score, 1);
        meterLabel.textContent = "Сила пароля: " + r.label;
        if (onInfo) onInfo(r);
      } catch (_) { /* ігноруємо */ }
    }, 150);
  });
  return { input, node: h("div", {}, h("label", {}, labelText), input, meter, meterLabel, checks) };
}

// ---------- навігація ----------
function renderNav() {
  const route = location.hash.replace(/^#/, "") || "/";
  const link = (href, text) => h("a", { href: "#" + href, class: route.startsWith(href) && href !== "/" ? "active" : "" }, text);
  const items = [];
  if (me) {
    items.push(link("/profile", "Профіль"));
    if (me.role === "admin") items.push(link("/admin", "Адмін-панель"));
    items.push(link("/mailbox", "Dev-пошта"));
    items.push(h("button", { onclick: logout }, "Вийти (" + me.email + ")"));
  } else {
    items.push(link("/login", "Вхід"), link("/register", "Реєстрація"), link("/mailbox", "Dev-пошта"));
  }
  $nav.replaceChildren(...items);
}

async function logout() {
  await api("/logout", { method: "POST" });
  me = null;
  go("/login");
  route();
}

// ---------- сторінки ----------
function viewRegister() {
  const msg = h("div");
  const name = h("input", { type: "text", maxlength: 80, required: true, autocomplete: "name" });
  const email = h("input", { type: "email", required: true, autocomplete: "email" });
  const pw = passwordField();
  const cap = h("input", { type: "text", maxlength: 8, required: true, autocomplete: "off", placeholder: "Введіть символи з картинки" });
  const img = h("img", { alt: "CAPTCHA", width: 190, height: 64 });
  const reload = () => { img.src = "/api/captcha?t=" + Date.now(); cap.value = ""; };
  reload();

  const form = h("form", {
    novalidate: true,
    onsubmit: async e => {
      e.preventDefault();
      try {
        const r = await api("/register", { method: "POST", body: { name: name.value, email: email.value, password: pw.input.value, captcha: cap.value } });
        form.replaceChildren(alertBox("ok", r.message), h("p", {}, "Лист з посиланням активації надіслано на ", h("b", {}, email.value), ". Відкрийте його у ", h("a", { href: "#/mailbox" }, "Dev-пошті"), "."));
      } catch (err) {
        showMsg(msg, "error", err.message, err.data && err.data.problems);
        reload();
      }
    },
  },
    field("Ім'я", name), field("Email", email), pw.node,
    h("label", {}, "CAPTCHA"),
    h("div", { class: "captcha" }, img, h("button", { type: "button", class: "btn secondary small", onclick: reload }, "Оновити")),
    h("div", { style: null }, cap),
    msg,
    h("button", { class: "btn block", type: "submit" }, "Зареєструватися"),
    h("div", { class: "links" }, h("span"), h("a", { href: "#/login" }, "Вже є акаунт? Увійти")),
  );
  render(h("div", { class: "card narrow" }, h("h1", {}, "Реєстрація"), h("p", { class: "sub" }, "Створіть обліковий запис"), form));
}

function viewLogin(query) {
  const msg = h("div");
  const errors = { oidc: "Не вдалося увійти через зовнішнього провайдера", oidc_email: "Провайдер не підтвердив ваш email", blocked: "Обліковий запис заблоковано адміністратором" };
  if (query.get("error")) msg.append(alertBox("error", errors[query.get("error")] || "Помилка входу"));
  const email = h("input", { type: "email", required: true, autocomplete: "username" });
  const password = h("input", { type: "password", required: true, autocomplete: "current-password" });
  const form = h("form", {
    novalidate: true,
    onsubmit: async e => {
      e.preventDefault();
      try {
        const r = await api("/login", { method: "POST", body: { email: email.value, password: password.value } });
        if (r.status === "2fa_required") return viewLogin2fa();
        me = r.user; go("/profile"); route();
      } catch (err) {
        showMsg(msg, "error", err.message);
        if (err.data && err.data.code === "not_activated") {
          msg.append(h("button", { type: "button", class: "btn secondary small", onclick: async () => {
            await api("/activate/resend", { method: "POST", body: { email: email.value } });
            showMsg(msg, "ok", "Новий лист активації надіслано");
          } }, "Надіслати лист активації повторно"));
        }
        password.value = "";
      }
    },
  },
    field("Email", email), field("Пароль", password), msg,
    h("button", { class: "btn block", type: "submit" }, "Увійти"),
    h("div", { class: "divider" }, "або"),
    h("a", { class: "btn secondary block", href: "/api/oidc/login" }, "Увійти через OpenID Connect"),
    h("div", { class: "links" }, h("a", { href: "#/forgot" }, "Забули пароль?"), h("a", { href: "#/register" }, "Реєстрація")),
  );
  render(h("div", { class: "card narrow" }, h("h1", {}, "Вхід"), h("p", { class: "sub" }, "Увійдіть у свій обліковий запис"), form));
}

function viewLogin2fa() {
  const msg = h("div");
  const code = h("input", { type: "text", class: "otp", inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code", required: true, autofocus: true });
  const form = h("form", {
    novalidate: true,
    onsubmit: async e => {
      e.preventDefault();
      try {
        const r = await api("/login/2fa", { method: "POST", body: { code: code.value } });
        me = r.user; go("/profile"); route();
      } catch (err) {
        showMsg(msg, "error", err.message);
        code.value = "";
        if (err.status === 401 && /завершилась/.test(err.message)) setTimeout(() => { go("/login"); route(); }, 1200);
      }
    },
  }, field("Код з додатку-автентифікатора", code), msg, h("button", { class: "btn block", type: "submit" }, "Підтвердити"));
  render(h("div", { class: "card narrow" }, h("h1", {}, "Двофакторна автентифікація"), h("p", { class: "sub" }, "Введіть 6-значний код з Google Authenticator / Authy"), form));
  code.focus();
}

function viewActivate(token) {
  const box = h("div", {}, h("p", {}, "Перевіряємо посилання…"));
  render(h("div", { class: "card narrow" }, h("h1", {}, "Активація облікового запису"), box));
  api("/activate", { method: "POST", body: { token } })
    .then(r => box.replaceChildren(alertBox("ok", r.message), h("a", { class: "btn", href: "#/login" }, "Перейти до входу")))
    .catch(err => box.replaceChildren(alertBox("error", err.message), h("a", { href: "#/login" }, "До сторінки входу")));
}

function viewForgot() {
  const msg = h("div");
  const email = h("input", { type: "email", required: true });
  const form = h("form", {
    novalidate: true,
    onsubmit: async e => {
      e.preventDefault();
      try {
        const r = await api("/password/forgot", { method: "POST", body: { email: email.value } });
        showMsg(msg, "ok", r.message);
        msg.append(h("a", { href: "#/mailbox" }, "Відкрити Dev-пошту"));
      } catch (err) { showMsg(msg, "error", err.message); }
    },
  }, field("Email вашого облікового запису", email), msg, h("button", { class: "btn block", type: "submit" }, "Надіслати посилання"),
    h("div", { class: "links" }, h("a", { href: "#/login" }, "Назад до входу"), h("span")));
  render(h("div", { class: "card narrow" }, h("h1", {}, "Відновлення пароля"), h("p", { class: "sub" }, "Ми надішлемо посилання для встановлення нового пароля"), form));
}

function viewReset(token) {
  const msg = h("div");
  const pw = passwordField("Новий пароль");
  const form = h("form", {
    novalidate: true,
    onsubmit: async e => {
      e.preventDefault();
      try {
        const r = await api("/password/reset", { method: "POST", body: { token, password: pw.input.value } });
        form.replaceChildren(alertBox("ok", r.message), h("a", { class: "btn", href: "#/login" }, "Перейти до входу"));
      } catch (err) { showMsg(msg, "error", err.message, err.data && err.data.problems); }
    },
  }, pw.node, msg, h("button", { class: "btn block", type: "submit" }, "Зберегти новий пароль"));
  render(h("div", { class: "card narrow" }, h("h1", {}, "Новий пароль"), h("p", { class: "sub" }, "Придумайте новий пароль, що відповідає політиці безпеки"), form));
}

function statusBadge(ok, yes, no, noKind = "warn") { return h("span", { class: "badge " + (ok ? "ok" : noKind) }, ok ? yes : no); }

function viewProfile() {
  const twofa = h("div");
  const draw2fa = () => {
    if (me.totp_enabled) {
      const msg = h("div"), pass = h("input", { type: "password", autocomplete: "current-password" }), code = h("input", { type: "text", inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code" });
      twofa.replaceChildren(
        h("p", {}, statusBadge(true, "Увімкнено", "")), h("p", { class: "sub" }, "Щоб вимкнути 2FA, підтвердіть пароль та поточний код."),
        field("Пароль", pass), field("Код 2FA", code), msg,
        h("p", {}, h("button", { class: "btn danger", onclick: async () => {
          try { await api("/2fa/disable", { method: "POST", body: { password: pass.value, code: code.value } }); me = await api("/me"); draw2fa(); }
          catch (err) { showMsg(msg, "error", err.message); }
        } }, "Вимкнути 2FA")));
    } else {
      twofa.replaceChildren(h("p", {}, statusBadge(false, "", "Вимкнено", "gray")),
        h("p", { class: "sub" }, "Додатковий захист: при вході потрібен одноразовий код (TOTP)."),
        h("button", { class: "btn", onclick: startSetup }, "Увімкнути 2FA"));
    }
  };
  const startSetup = async () => {
    const r = await api("/2fa/setup", { method: "POST" });
    const msg = h("div"), code = h("input", { type: "text", inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code", placeholder: "6-значний код" });
    twofa.replaceChildren(
      h("p", {}, "1. Відскануйте QR-код у Google Authenticator / Authy / Microsoft Authenticator."),
      h("div", { class: "qr" }, h("img", { src: r.qr, alt: "QR-код 2FA" }), h("div", {}, h("div", { class: "sub" }, "Або введіть ключ вручну:"), h("code", { class: "secret", id: "totp-secret" }, r.secret))),
      h("p", {}, "2. Введіть код з додатку для підтвердження:"), code, msg,
      h("p", {}, h("button", { class: "btn", onclick: async () => {
        try { await api("/2fa/enable", { method: "POST", body: { code: code.value } }); me = await api("/me"); draw2fa(); }
        catch (err) { showMsg(msg, "error", err.message); }
      } }, "Підтвердити та увімкнути"), " ", h("button", { class: "btn secondary", onclick: draw2fa }, "Скасувати")));
  };
  draw2fa();
  render(
    h("div", { class: "card" }, h("h1", {}, "Мій профіль"),
      h("dl", { class: "kv" },
        h("dt", {}, "Ім'я"), h("dd", {}, me.name),
        h("dt", {}, "Email"), h("dd", {}, me.email),
        h("dt", {}, "Роль"), h("dd", {}, me.role === "admin" ? "Адміністратор" : "Користувач"),
        h("dt", {}, "Статус активації"), h("dd", { id: "activation-status" }, statusBadge(me.is_activated, "Активовано", "Не активовано")),
        h("dt", {}, "Вхід через"), h("dd", {}, me.oidc ? "Зовнішній провайдер (OIDC)" : "Email та пароль"),
        h("dt", {}, "Зареєстровано"), h("dd", {}, fmt(me.created_at)))),
    h("div", { class: "card" }, h("h2", {}, "Двофакторна автентифікація (2FA)"), twofa),
  );
}

async function viewAdmin() {
  const content = h("div");
  const tabs = h("div", { class: "tabs" });
  let current = "users";
  const tabDefs = [["users", "Користувачі"], ["log", "Журнал входів"], ["summary", "Зведення спроб"]];
  const drawTabs = () => tabs.replaceChildren(...tabDefs.map(([k, t]) => h("button", { class: k === current ? "active" : "", onclick: () => { current = k; drawTabs(); load(); } }, t)));

  const resultBadge = r => {
    const kind = { success: "ok", fail: "bad", lockout: "bad", locked: "bad", blocked: "bad", admin_block: "warn", admin_unblock: "ok", password_ok: "gray", not_activated: "warn", password_reset: "gray" }[r] || "gray";
    return h("span", { class: "badge " + kind }, r);
  };

  async function load() {
    content.replaceChildren(h("p", { class: "sub" }, "Завантаження…"));
    if (current === "users") {
      const users = await api("/admin/users");
      content.replaceChildren(h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["ID", "Користувач", "Роль", "Активація", "2FA", "Статус", "Невдалі спроби", ""].map(t => h("th", {}, t)))),
        h("tbody", {}, users.map(u => h("tr", { "data-email": u.email },
          h("td", {}, u.id),
          h("td", {}, h("b", {}, u.name), h("div", { class: "sub", style: null }, u.email)),
          h("td", {}, u.role === "admin" ? "Адмін" : "Користувач"),
          h("td", {}, statusBadge(u.is_activated, "Так", "Ні")),
          h("td", {}, statusBadge(u.totp_enabled, "Увімк.", "—", "gray")),
          h("td", {}, u.is_blocked ? h("span", { class: "badge bad" }, "Заблоковано") : u.locked_until ? h("span", { class: "badge warn" }, "Тимчасово (brute force) до " + new Date(u.locked_until * 1000).toLocaleTimeString("uk-UA")) : h("span", { class: "badge ok" }, "Активний")),
          h("td", {}, u.failed_attempts),
          h("td", {}, me.id === u.id ? "" : u.is_blocked || u.locked_until
            ? h("button", { class: "btn small secondary", onclick: async () => { await api(`/admin/users/${u.id}/unblock`, { method: "POST" }); load(); } }, "Розблокувати")
            : h("button", { class: "btn small danger", onclick: async () => { await api(`/admin/users/${u.id}/block`, { method: "POST" }); load(); } }, "Заблокувати")),
        ))))));
    } else if (current === "log") {
      const email = h("input", { type: "search", placeholder: "Фільтр за email" });
      const result = h("select", {}, h("option", { value: "" }, "Усі результати"), ...["success", "fail", "lockout", "locked", "blocked", "not_activated", "password_ok", "password_reset", "admin_block", "admin_unblock"].map(r => h("option", { value: r }, r)));
      const tbody = h("tbody");
      const refresh = async () => {
        const rows = await api("/admin/logs?" + new URLSearchParams({ email: email.value, result: result.value }));
        tbody.replaceChildren(...rows.map(r => h("tr", {}, h("td", {}, fmt(r.ts)), h("td", {}, r.email), h("td", {}, r.ip), h("td", {}, resultBadge(r.result)), h("td", {}, r.detail))));
        if (!rows.length) tbody.append(h("tr", {}, h("td", { colspan: 5 }, "Записів немає")));
      };
      email.addEventListener("input", refresh); result.addEventListener("change", refresh);
      content.replaceChildren(h("div", { class: "row" }, email, result), h("br"), h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Час", "Email", "IP", "Результат", "Деталі"].map(t => h("th", {}, t)))), tbody)));
      refresh();
    } else {
      const rows = await api("/admin/attempts");
      content.replaceChildren(h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Email", "Невдалих спроб", "Успішних входів", "Блокувань", "Остання активність"].map(t => h("th", {}, t)))),
        h("tbody", {}, rows.map(r => h("tr", {}, h("td", {}, r.email), h("td", {}, h("b", {}, r.failed)), h("td", {}, r.success), h("td", {}, r.lockouts), h("td", {}, fmt(r.last_ts))))))));
    }
  }
  drawTabs();
  render(h("div", { class: "card" }, h("h1", {}, "Адмін-панель"), h("p", { class: "sub" }, "Користувачі, журнал входів, блокування облікових записів"), tabs, content));
  load();
}

async function viewMailbox() {
  const box = h("div");
  render(h("div", { class: "card" }, h("h1", {}, "Dev-пошта"), h("p", { class: "sub" }, "Локальна заміна поштового сервера: тут з'являються всі листи, які надсилає система (активація, відновлення пароля)."), box,
    h("button", { class: "btn secondary small", onclick: viewMailbox }, "Оновити")));
  try {
    const mails = await api("/dev/mailbox");
    if (!mails.length) return box.replaceChildren(alertBox("info", "Листів поки немає"));
    box.replaceChildren(...mails.map(m => h("div", { class: "mail" },
      h("h3", {}, m.subject), h("div", { class: "meta" }, "Кому: " + m.to_addr + " · " + fmt(m.ts)),
      h("pre", {}, ...m.body.split(/(https?:\/\/\S+)/).map(part => /^https?:\/\//.test(part) ? h("a", { href: part }, part) : part)))));
  } catch (err) { box.replaceChildren(alertBox("error", "Dev-пошта вимкнена (DEV_MAILBOX=0)")); }
}

function viewHome() {
  if (me) return go("/profile");
  render(h("div", { class: "card narrow" }, h("h1", {}, "Безпечне керування обліковими записами"),
    h("p", { class: "sub" }, "Реєстрація, CAPTCHA, активація через email, захист від brute force, 2FA, OpenID Connect, відновлення пароля, RBAC."),
    h("a", { class: "btn block", href: "#/login" }, "Увійти"), h("a", { class: "btn secondary block", href: "#/register" }, "Створити акаунт")));
}

// ---------- маршрутизатор ----------
async function route() {
  const [path, qs] = (location.hash.replace(/^#/, "") || "/").split("?");
  const query = new URLSearchParams(qs || "");
  if (me === null) { try { me = await api("/me"); } catch (_) { me = null; } }
  renderNav();
  const parts = path.split("/").filter(Boolean);
  const needLogin = fn => me ? fn() : (go("/login"));
  switch (parts[0]) {
    case undefined: return viewHome();
    case "register": return viewRegister();
    case "login": return me ? go("/profile") : viewLogin(query);
    case "activate": return viewActivate(parts[1] || "");
    case "forgot": return viewForgot();
    case "reset": return viewReset(parts[1] || "");
    case "profile": return needLogin(viewProfile);
    case "admin": return needLogin(() => me.role === "admin" ? viewAdmin() : render(alertBox("error", "Недостатньо прав (потрібна роль адміністратора)")));
    case "mailbox": return viewMailbox();
    default: return render(alertBox("error", "Сторінку не знайдено"));
  }
}
window.addEventListener("hashchange", route);
route();
