"""
ShopNow — intentionally vulnerable web-shop lab, as a PURE-PYTHON Cloudflare
Worker (Python Workers / Pyodide runtime). No Flask, no external packages, so
it runs under `npx wrangler dev` and deploys to Cloudflare.

FOR AUTHORIZED SECURITY TRAINING ONLY. Every route is deliberately insecure.
Do NOT expose this publicly. Login (hardcoded): admin / admin.

Runtime notes (serverless sandbox, honest):
- SQLite lives at /tmp/shopnow.sqlite3 on Pyodide's in-memory filesystem and
  is re-seeded per isolate (idempotent). Sessions/cart are kept in an in-memory
  store for the lab.
- OS command injection is realised here as Python code injection (eval/exec) at
  /admin/exec — the equivalent "injection into a command interpreter" sink,
  because the Workers sandbox has no OS shell/subprocess.
- HTTP request smuggling requires a vulnerable FRONT-END proxy in front of the
  app; /api/search is the practice target but true smuggling cannot be shown by
  the app alone. A real OS-level + subprocess + lxml variant lives in src/app.py
  (plain Flask) for hosts that have those.
"""
# Cloudflare Python Workers SDK (workers-py). Bundled into the Worker by
# pywrangler (`uvx --from workers-py pywrangler dev/deploy`). In offline unit
# tests, tests/conftest.py stubs this module with minimal WorkerEntrypoint /
# Response classes so src/worker.py stays importable without the runtime.
from workers import WorkerEntrypoint, Response
import sqlite3
import os
import json
import base64
import hashlib
import hmac
import time
import pickle
import html as _html
import urllib.parse
import xml.sax.saxutils as _x  # noqa: F401  (available in stdlib)

DB_PATH = "/tmp/shopnow.sqlite3"
UPLOAD_DIR = "/tmp/shopnow_uploads"
JWT_SECRET = "s3cr3t"            # weak on purpose
SESSIONS = {}                   # sid -> {"uid":..., "role":..., "cart":{}, "prefs":{}}

# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE,
          password TEXT, role TEXT DEFAULT 'customer', balance REAL DEFAULT 100.0,
          api_key TEXT, is_vip INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS products(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT,
          price REAL, category TEXT, stock INTEGER DEFAULT 10, emoji TEXT);
        CREATE TABLE IF NOT EXISTS orders(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, total REAL,
          status TEXT DEFAULT 'pending', created_at TEXT);
        CREATE TABLE IF NOT EXISTS reviews(
          id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER,
          author TEXT, body TEXT);
        CREATE TABLE IF NOT EXISTS coupons(code TEXT PRIMARY KEY, percent INTEGER);
        CREATE TABLE IF NOT EXISTS messages(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, body TEXT);
        """
    )
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        conn.execute("INSERT INTO users(username,password,role,balance,api_key,is_vip)"
                     " VALUES('admin','admin','admin',100000,'ADMIN-KEY-9931',1)")
        conn.execute("INSERT INTO users(username,password,role,balance,api_key,is_vip)"
                     " VALUES('carlos','montoya','customer',50,'CUST-KEY-1020',0)")
    if conn.execute("SELECT COUNT(*) c FROM products").fetchone()["c"] == 0:
        prods = [
            ("Wireless Headphones", "Noise-cancelling over-ear headphones.", 89.99, "audio", 25, "🎧"),
            ("Mechanical Keyboard", "RGB hot-swappable mechanical keyboard.", 119.0, "accessories", 40, "⌨️"),
            ("4K Monitor", "27-inch 4K IPS display with USB-C.", 349.5, "displays", 12, "🖥️"),
            ("USB-C Charger", "65W GaN fast charger.", 29.99, "accessories", 100, "🔌"),
            ("Webcam Pro", "1080p webcam with privacy shutter.", 54.0, "accessories", 30, "📷"),
            ("Gaming Mouse", "16000 DPI ergonomic gaming mouse.", 39.99, "accessories", 60, "🖱️"),
            ("Leather Wallet", "RFID-blocking genuine leather wallet.", 24.99, "lifestyle", 80, "👛"),
            ("Secret Prototype X1", "Internal only. Not for sale yet.", 999999.0, "hidden", 1, "🧪"),
        ]
        conn.executemany("INSERT INTO products(name,description,price,category,stock,emoji)"
                         " VALUES(?,?,?,?,?,?)", prods)
        conn.executemany("INSERT INTO reviews(product_id,author,body) VALUES(?,?,?)",
                         [(1, "mike", "Great sound!"), (2, "lucy", "Love the switches.")])
        conn.executemany("INSERT INTO coupons(code,percent) VALUES(?,?)",
                         [("WELCOME10", 10), ("VIP50", 50)])
    conn.commit()
    conn.close()
    try:
        with open(os.path.join(UPLOAD_DIR, "readme.txt"), "w") as f:
            f.write("ShopNow uploads directory.\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Tiny request/response helpers
# ---------------------------------------------------------------------------

class Req:
    def __init__(self, request, body_text):
        self.method = request.method
        self.url = str(request.url)
        p = urllib.parse.urlparse(self.url)
        self.path = p.path
        self.query = {k: v[-1] for k, v in urllib.parse.parse_qs(
            p.query, keep_blank_values=True).items()}
        self.raw_body = body_text or ""
        self.form = {k: v[-1] for k, v in urllib.parse.parse_qs(
            self.raw_body, keep_blank_values=True).items()}
        self._h = request.headers

    def header(self, name, default=None):
        v = self._h.get(name)
        return v if v is not None else default

    def cookie(self, name):
        raw = self.header("Cookie") or ""
        for part in raw.split(";"):
            if "=" in part:
                k, val = part.strip().split("=", 1)
                if k == name:
                    return urllib.parse.unquote(val)
        return None

    def json(self):
        try:
            return json.loads(self.raw_body)
        except Exception:
            return {}


def resp(body, status=200, ctype="text/html; charset=utf-8", extra=None, origin=None):
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("latin-1")
    headers = {"Content-Type": ctype}
    # VULN: reflect Origin + allow credentials (CORS); never send frame/CSP headers
    if origin:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
    if extra:
        headers.update(extra)
    return Response(body, status=status, headers=headers)


def redirect(location, extra=None):
    h = {"Location": location}
    if extra:
        h.update(extra)
    return Response("", status=302, headers=h)


def e(s):
    return _html.escape(str(s))


# ---------------------------------------------------------------------------
# Sessions / JWT (weak on purpose)
# ---------------------------------------------------------------------------

def get_session(req):
    sid = req.cookie("sid")
    if sid and sid in SESSIONS:
        return sid, SESSIONS[sid]
    return None, None


def new_session():
    sid = base64.urlsafe_b64encode(os.urandom(12)).decode()
    SESSIONS[sid] = {"uid": None, "role": None, "cart": {}, "prefs": {"theme": "light"}}
    return sid


def current_user(sess):
    if not sess or not sess.get("uid"):
        return None
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (sess["uid"],)).fetchone()
    conn.close()
    return row


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(payload):
    h = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64u(json.dumps(payload).encode())
    sig = hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64u(sig)}"


def jwt_decode(token):
    h, p, s = token.split(".")
    header = json.loads(b64u_dec(h))
    payload = json.loads(b64u_dec(p))
    if header.get("alg") == "none":           # VULN: unsigned tokens accepted
        return payload
    exp = b64u(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(exp, s):
        raise ValueError("bad signature")
    return payload


# ---------------------------------------------------------------------------
# Layout (responsive UI)
# ---------------------------------------------------------------------------

CSS = """
:root{--bg:#0f172a;--card:#ffffff;--ink:#0f172a;--muted:#64748b;--brand:#2563eb;
--accent:#059669;--line:#e2e8f0;--soft:#f1f5f9}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;
background:var(--soft);color:var(--ink);line-height:1.5}
a{color:var(--brand);text-decoration:none}
header{position:sticky;top:0;z-index:20;background:rgba(15,23,42,.97);
backdrop-filter:blur(6px);color:#fff}
.nav{max-width:1120px;margin:auto;display:flex;align-items:center;gap:8px;
padding:12px 18px;flex-wrap:wrap}
.brand{font-weight:800;font-size:20px;color:#fff;margin-right:8px}
.nav a{color:#cbd5e1;padding:8px 10px;border-radius:8px;font-size:14px}
.nav a:hover{background:rgba(255,255,255,.08);color:#fff}
.nav .sp{flex:1}
.toggle{display:none;background:none;border:1px solid #334155;color:#fff;
font-size:20px;border-radius:8px;padding:4px 10px;cursor:pointer}
.chip{font-size:12px;color:#94a3b8;padding:6px 8px}
.wrap{max-width:1120px;margin:22px auto;padding:0 18px}
.hero{background:linear-gradient(135deg,#1e3a8a,#2563eb);color:#fff;border-radius:18px;
padding:34px;margin-bottom:22px;box-shadow:0 10px 30px rgba(37,99,235,.25)}
.hero h1{margin:0 0 6px;font-size:clamp(26px,4vw,40px)}
.hero p{margin:0;opacity:.9}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;
padding:18px;margin:14px 0;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(220px,1fr))}
.prod{display:flex;flex-direction:column}
.prod .thumb{font-size:52px;text-align:center;background:var(--soft);border-radius:12px;
padding:22px 0;margin-bottom:10px}
.prod h3{margin:.2em 0;font-size:17px}
.price{color:var(--accent);font-weight:800;font-size:18px}
.muted{color:var(--muted);font-size:13px}
.btn{background:var(--brand);color:#fff;border:none;padding:10px 16px;border-radius:10px;
cursor:pointer;font-weight:600;display:inline-block;text-align:center}
.btn:hover{filter:brightness(1.07)}
.btn.sec{background:#e2e8f0;color:#0f172a}
input,textarea,select{width:100%;padding:11px;border:1px solid var(--line);
border-radius:10px;margin:6px 0;font:inherit;background:#fff}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:9px;border-bottom:1px solid var(--line);font-size:14px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.auth{max-width:380px;margin:40px auto}
.err{color:#b91c1c;font-size:14px;min-height:18px}
pre{background:#0b1220;color:#d1fae5;padding:14px;border-radius:10px;overflow:auto;font-size:13px}
code{background:var(--soft);padding:2px 6px;border-radius:6px}
footer{max-width:1120px;margin:30px auto;padding:0 18px;color:var(--muted);font-size:13px}
@media(max-width:720px){
 .toggle{display:block;margin-left:auto}
 .nav .links{display:none;width:100%;flex-direction:column}
 .nav.open .links{display:flex}
 .nav .links a{width:100%}
 .nav .sp{display:none}
}
"""

NAVJS = "function tnav(){document.querySelector('.nav').classList.toggle('open')}"


def layout(inner, user=None):
    links = ('<a href="/">Home</a><a href="/products">Shop</a>'
             '<a href="/cart">Cart</a><a href="/orders">Orders</a>'
             '<a href="/account">Account</a>')
    if user and user["role"] == "admin":
        links += '<a href="/admin">Admin</a>'
    if user:
        right = (f'<span class="chip">👤 {e(user["username"])}</span>'
                 '<a href="/logout">Logout</a>')
    else:
        right = '<a href="/login">Login</a><a href="/register">Sign up</a>'
    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShopNow</title><style>{CSS}</style></head><body>
<header><div class="nav">
 <a class="brand" href="/">🛍️ ShopNow</a>
 <button class="toggle" onclick="tnav()">☰</button>
 <div class="links">{links}</div>
 <span class="sp"></span><div class="links" style="flex-direction:row">{right}</div>
</div></header>
<div class="wrap">{inner}</div>
<footer>© ShopNow — demo electronics store.</footer>
<script>{NAVJS}</script></body></html>"""


# ---------------------------------------------------------------------------
# Route handlers  (return a Response)
# ---------------------------------------------------------------------------

def need_login(sess):
    return bool(sess and sess.get("uid"))


def h_home(req, sess, user, origin):
    if not user:
        inner = ('<div class="hero"><h1>ShopNow</h1>'
                 '<p>Premium electronics, delivered fast.</p></div>'
                 '<div class="card">Please <a href="/login">log in</a> to start '
                 'shopping. Demo account: <code>admin / admin</code>.</div>')
        return resp(layout(inner, user), origin=origin)
    msg = req.query.get("msg", "Welcome back! Enjoy free shipping this week.")
    inner = (f'<div class="hero"><h1>Hi {e(user["username"])} 👋</h1>'
             f'<p>{msg}</p></div>'  # VULN: reflected XSS via ?msg=
             '<div class="card"><div class="row">'
             '<a class="btn" href="/products">Browse products</a>'
             '<a class="btn sec" href="/account">My account</a></div></div>')
    return resp(layout(inner, user), origin=origin)


def h_login(req, sess, user, origin):
    if req.method == "POST":
        u = req.form.get("username", "")
        p = req.form.get("password", "")
        conn = db()
        # VULN: SQL injection (string-built auth query)
        q = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
        try:
            row = conn.execute(q).fetchone()
        except Exception as ex:
            conn.close()
            return _login_page(user, f"SQL error: {e(ex)}", origin)  # info disc
        conn.close()
        if row:
            sid = req.cookie("sid")
            if not sid or sid not in SESSIONS:
                sid = new_session()
            SESSIONS[sid].update({"uid": row["id"], "role": row["role"]})
            return redirect("/", extra={"Set-Cookie": f"sid={sid}; Path=/"})
        return _login_page(user, "Invalid credentials", origin)
    return _login_page(user, "", origin)


def _login_page(user, err, origin):
    inner = f"""<div class="card auth"><h2>Welcome back</h2>
      <form method="post"><div class="err">{err}</div>
      <input name="username" placeholder="Username" autofocus>
      <input name="password" type="password" placeholder="Password">
      <button class="btn" style="width:100%">Sign in</button></form>
      <p class="muted">Demo: admin / admin · <a href="/register">Create account</a></p></div>"""
    return resp(layout(inner, user), origin=origin)


def h_logout(req, sess, user, origin):
    sid = req.cookie("sid")
    if sid in SESSIONS:
        del SESSIONS[sid]
    return redirect("/", extra={"Set-Cookie": "sid=; Path=/; Max-Age=0"})


def h_register(req, sess, user, origin):
    if req.method == "POST":
        u = req.form.get("username", "")
        p = req.form.get("password", "")
        role = req.form.get("role", "customer")   # VULN: mass-assignment of role
        conn = db()
        try:
            conn.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",
                         (u, p, role))
            conn.commit()
        except Exception as ex:
            conn.close()
            return resp(layout(f'<div class="card">{e(ex)}</div>', user), origin=origin)
        conn.close()
        return redirect("/login")
    inner = """<div class="card auth"><h2>Create account</h2>
      <form method="post">
      <input name="username" placeholder="Username">
      <input name="password" type="password" placeholder="Password">
      <button class="btn" style="width:100%">Sign up</button></form></div>"""
    return resp(layout(inner, user), origin=origin)


def h_products(req, sess, user, origin):
    conn = db()
    q = req.query.get("q")
    cat = req.query.get("category")
    sql = "SELECT * FROM products WHERE category!='hidden'"
    if q is not None:
        # VULN: SQL injection in product search
        sql = (f"SELECT * FROM products WHERE name LIKE '%{q}%' "
               f"OR description LIKE '%{q}%'")
    elif cat:
        sql = f"SELECT * FROM products WHERE category='{cat}'"
    try:
        rows = conn.execute(sql).fetchall()
    except Exception as ex:
        conn.close()
        return resp(layout(f'<div class="card">Query error: {e(ex)}</div>', user),
                    origin=origin)  # info disclosure
    conn.close()
    cards = "".join(
        f'<div class="card prod"><div class="thumb">{r["emoji"] or "📦"}</div>'
        f'<h3>{e(r["name"])}</h3><p class="muted">{e(r["description"])}</p>'
        f'<p class="price">${r["price"]:.2f}</p>'
        f'<a class="btn" href="/product/{r["id"]}">View</a></div>' for r in rows)
    qval = e(req.query.get("q", ""))
    inner = (f'<div class="card"><form method="get" class="row">'
             f'<input name="q" value="{qval}" placeholder="Search products..." '
             f'style="flex:1">'
             f'<button class="btn">Search</button></form></div>'
             f'<div class="grid">{cards or "<p>No products.</p>"}</div>')
    return resp(layout(inner, user), origin=origin)


def h_product(req, sess, user, origin, pid):
    conn = db()
    if req.method == "POST":
        body = req.form.get("body", "")
        # VULN: stored XSS (review rendered unescaped)
        conn.execute("INSERT INTO reviews(product_id,author,body) VALUES(?,?,?)",
                     (pid, user["username"], body))
        conn.commit()
    p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p:
        conn.close()
        return resp(layout('<div class="card">Not found</div>', user), status=404,
                    origin=origin)
    reviews = conn.execute("SELECT * FROM reviews WHERE product_id=?", (pid,)).fetchall()
    conn.close()
    rev = "".join(f'<div class="card"><b>{e(r["author"])}</b>: {r["body"]}</div>'
                  for r in reviews)  # VULN: body not escaped -> stored XSS
    inner = f"""<div class="card"><div class="row" style="align-items:flex-start">
      <div class="thumb" style="font-size:72px">{p['emoji'] or '📦'}</div>
      <div style="flex:1;min-width:220px"><h2>{e(p['name'])}</h2>
      <p class="muted">{e(p['description'])}</p>
      <p class="price">${p['price']:.2f}</p>
      <form method="post" action="/cart/add" class="row">
        <input type="hidden" name="product_id" value="{p['id']}">
        <input type="number" name="qty" value="1" style="width:90px">
        <button class="btn">Add to cart</button></form></div></div></div>
      <h3>Reviews</h3>{rev or '<p class="muted">No reviews yet.</p>'}
      <div class="card"><form method="post">
      <textarea name="body" placeholder="Write a review"></textarea>
      <button class="btn">Submit review</button></form></div>"""
    return resp(layout(inner, user), origin=origin)


def h_cart_add(req, sess, user, origin):
    pid = req.form.get("product_id", "")
    try:
        qty = int(req.form.get("qty", "1"))       # VULN: negative qty allowed
    except Exception:
        qty = 1
    cart = sess["cart"]
    cart[pid] = cart.get(pid, 0) + qty
    return redirect("/cart")


def h_cart(req, sess, user, origin):
    conn = db()
    rows, total = [], 0.0
    for pid, qty in sess["cart"].items():
        p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if p:
            line = p["price"] * qty
            total += line
            rows.append(f'<tr><td>{e(p["name"])}</td><td>{qty}</td>'
                        f'<td>${line:.2f}</td></tr>')
    conn.close()
    inner = f"""<div class="card"><h2>Your cart</h2>
      <table><tr><th>Item</th><th>Qty</th><th>Subtotal</th></tr>
      {''.join(rows) or '<tr><td colspan=3 class=muted>Cart is empty.</td></tr>'}</table>
      <p class="price">Total: ${total:.2f}</p>
      <!-- VULN: checkout form has no CSRF token -->
      <form method="post" action="/checkout" class="row">
        <input name="coupon" placeholder="Coupon code" style="flex:1">
        <button class="btn">Checkout</button></form></div>"""
    return resp(layout(inner, user), origin=origin)


def h_checkout(req, sess, user, origin):
    conn = db()
    total = 0.0
    for pid, qty in sess["cart"].items():
        p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if p:
            total += p["price"] * qty       # negative qty can lower total
    coupon = req.form.get("coupon", "")
    percent = 0
    if coupon:
        c = conn.execute("SELECT * FROM coupons WHERE code=?", (coupon,)).fetchone()
        if c:
            percent = c["percent"]          # VULN: coupons stack/unbounded
    total = total * (100 - percent) / 100
    # VULN: no balance check; total may be negative (business logic)
    conn.execute("UPDATE users SET balance=balance-? WHERE id=?", (total, user["id"]))
    conn.execute("INSERT INTO orders(user_id,total,status,created_at) VALUES(?,?,?,?)",
                 (user["id"], total, "paid", time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    sess["cart"] = {}
    return redirect("/orders")


def h_orders(req, sess, user, origin):
    uid = req.query.get("user_id", str(sess["uid"]))   # VULN: IDOR via ?user_id=
    conn = db()
    rows = conn.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC",
                        (uid,)).fetchall()
    conn.close()
    items = "".join(
        f'<div class="card"><b>Order #{r["id"]}</b> — '
        f'<span class="price">${r["total"]:.2f}</span> '
        f'<span class="muted">[{e(r["status"])}] {e(r["created_at"])}</span></div>'
        for r in rows)
    return resp(layout(f'<h2>Orders</h2>{items or "<p class=muted>No orders.</p>"}',
                       user), origin=origin)


def h_account(req, sess, user, origin):
    token = jwt_encode({"sub": user["username"], "role": user["role"]})
    inner = f"""<div class="card"><h2>Account</h2>
      <table>
      <tr><th>User</th><td>{e(user['username'])}</td></tr>
      <tr><th>Role</th><td>{e(user['role'])}</td></tr>
      <tr><th>Balance</th><td>${user['balance']:.2f}</td></tr>
      <tr><th>API key</th><td><code>{e(user['api_key'])}</code></td></tr></table>
      <div class="row" style="margin-top:10px">
      <a class="btn sec" href="/account/settings">Settings</a>
      <a class="btn sec" href="/upload">Upload avatar</a></div></div>"""
    # VULN: session JWT (weak secret, alg:none honored on /api/me)
    return resp(layout(inner, user), origin=origin,
                extra={"Set-Cookie": f"session_jwt={token}; Path=/"})


def deep_merge(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def h_settings(req, sess, user, origin):
    prefs = sess.get("prefs", {"theme": "light"})
    if req.method == "POST":
        try:
            incoming = json.loads(req.form.get("prefs", "{}"))
        except Exception:
            incoming = {}
        deep_merge(prefs, incoming)   # VULN: prototype-pollution-style merge
        sess["prefs"] = prefs
    extra = ('<div class="card">✅ Admin mode unlocked via preferences.</div>'
             if prefs.get("isAdmin") else "")
    inner = f"""<div class="card"><h2>Settings</h2>
      <p>Current prefs: <code>{e(json.dumps(prefs))}</code></p>
      <form method="post"><textarea name="prefs">{{"theme":"dark"}}</textarea>
      <button class="btn">Save (JSON)</button></form></div>{extra}"""
    return resp(layout(inner, user), origin=origin)


def h_admin(req, sess, user, origin):
    # VULN: broken access control — trusts session role flag only
    if sess.get("role") != "admin":
        return resp(layout('<div class="card">Forbidden</div>', user), status=403,
                    origin=origin)
    conn = db()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    rows = "".join(f'<tr><td>{u["id"]}</td><td>{e(u["username"])}</td>'
                   f'<td>{e(u["role"])}</td><td>${u["balance"]:.2f}</td>'
                   f'<td><code>{e(u["api_key"])}</code></td></tr>' for u in users)
    inner = f"""<div class="card"><h2>Admin · users</h2><table>
      <tr><th>ID</th><th>User</th><th>Role</th><th>Balance</th><th>API key</th></tr>
      {rows}</table></div>
      <div class="card"><h3>Diagnostics console</h3>
      <form method="post" action="/admin/exec" class="row">
      <input name="cmd" placeholder="expression" value="1+1" style="flex:1">
      <button class="btn">Run</button></form>
      <p class="muted">Runs a quick server-side diagnostic expression.</p></div>"""
    return resp(layout(inner, user), origin=origin)


def h_admin_exec(req, sess, user, origin):
    if sess.get("role") != "admin":
        return resp("Forbidden", status=403, ctype="text/plain", origin=origin)
    cmd = req.form.get("cmd", "")
    # VULN: code/command injection — user input evaluated server-side.
    # (Workers sandbox has no OS shell; this is the equivalent interpreter sink.
    #  src/app.py uses subprocess+shell for true OS command injection.)
    try:
        out = repr(eval(cmd, {"__builtins__": __builtins__}, {"os": os}))
    except Exception as ex:
        out = f"{type(ex).__name__}: {ex}"
    return resp(f"<pre>{e(out)}</pre>", origin=origin)


def h_api_me(req, sess, user, origin):
    token = req.cookie("session_jwt")
    auth = req.header("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
    if not token:
        return resp(json.dumps({"error": "no token"}), status=401,
                    ctype="application/json", origin=origin)
    try:
        payload = jwt_decode(token)        # VULN: alg:none accepted
    except Exception as ex:
        return resp(json.dumps({"error": str(ex)}), status=401,
                    ctype="application/json", origin=origin)
    return resp(json.dumps(payload), ctype="application/json", origin=origin)


def h_api_products(req, sess, user, origin):
    f = req.query.get("filter")
    sql = "SELECT * FROM products"
    if f:
        sql += " WHERE " + f               # VULN: raw filter injection (SQL/NoSQL-style)
    conn = db()
    try:
        rows = [dict(r) for r in conn.execute(sql).fetchall()]
    except Exception as ex:
        conn.close()
        return resp(json.dumps({"error": str(ex)}), status=400,
                    ctype="application/json", origin=origin)   # info disclosure
    conn.close()
    return resp(json.dumps(rows), ctype="application/json", origin=origin)


def h_api_user(req, sess, user, origin, uid):
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    # VULN: no authz — leaks password/api_key of any user
    if not row:
        return resp("{}", status=404, ctype="application/json", origin=origin)
    return resp(json.dumps(dict(row)), ctype="application/json", origin=origin)


def h_import(req, sess, user, origin):
    result = ""
    if req.method == "POST":
        data = req.form.get("xml", "") or req.raw_body
        try:
            import xml.etree.ElementTree as ET  # VULN: XML parsing of untrusted input
            root = ET.fromstring(data)
            result = ET.tostring(root, encoding="unicode")
        except Exception as ex:
            result = str(ex)
    inner = f"""<div class="card"><h2>Import catalog (XML)</h2>
      <form method="post"><textarea name="xml" rows="7">&lt;catalog&gt;&lt;item&gt;sample&lt;/item&gt;&lt;/catalog&gt;</textarea>
      <button class="btn">Import</button></form><pre>{e(result)}</pre>
      <p class="muted">Note: external-entity (XXE) file exfiltration needs a
      parser that resolves external DTDs; the full OS/lxml variant is in
      src/app.py.</p></div>"""
    return resp(layout(inner, user), origin=origin)


async def h_fetch(req, sess, user, origin):
    url = req.query.get("url", "")
    if not url:
        return resp(layout('<div class="card">Provide ?url=</div>', user),
                    origin=origin)
    # VULN: SSRF — fetches any user-supplied URL
    try:
        from js import fetch as js_fetch
        r = await js_fetch(url)
        text = await r.text()
        data = str(text)[:4096]
    except Exception as ex:
        data = str(ex)
    return resp(f"<pre>{e(data)}</pre>", origin=origin)


def h_greet(req, sess, user, origin):
    name = req.query.get("name", "guest")
    # VULN: server-side template injection — {{expr}} is evaluated
    def render(tpl):
        out, i = "", 0
        while True:
            a = tpl.find("{{", i)
            if a < 0:
                out += tpl[i:]
                break
            out += tpl[i:a]
            b = tpl.find("}}", a)
            if b < 0:
                out += tpl[a:]
                break
            expr = tpl[a + 2:b].strip()
            try:
                out += str(eval(expr, {"__builtins__": __builtins__}, {}))
            except Exception as ex:
                out += f"[err:{ex}]"
            i = b + 2
        return out
    rendered = render(f"Hello, {name}!")
    inner = f'<div class="card"><h2>Greeting</h2><p>{rendered}</p></div>'
    return resp(layout(inner, user), origin=origin)


def _safe_in_tmp(path):
    return os.path.normpath(path)   # intentionally NOT confined (traversal)


def h_download(req, sess, user, origin):
    fname = req.query.get("file", "readme.txt")
    path = _safe_in_tmp(os.path.join(UPLOAD_DIR, fname))  # VULN: path traversal
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        return resp(data, ctype="application/octet-stream", origin=origin)
    except Exception as ex:
        return resp(str(ex), status=404, ctype="text/plain", origin=origin)


def h_upload(req, sess, user, origin):
    msg = ""
    if req.method == "POST":
        fname = req.form.get("filename", "avatar.txt")
        content = req.form.get("content", "")
        dest = os.path.join(UPLOAD_DIR, fname)     # VULN: no validation of name/type
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w") as fh:
                fh.write(content)
            msg = f"Saved to {dest}"
        except Exception as ex:
            msg = str(ex)
    inner = f"""<div class="card"><h2>Upload avatar</h2>
      <form method="post">
      <input name="filename" placeholder="filename" value="avatar.svg">
      <textarea name="content" placeholder="file content"></textarea>
      <button class="btn">Upload</button></form>
      <p class="muted">{e(msg)}</p>
      <p class="muted">Then read it back via <code>/download?file=...</code></p></div>"""
    return resp(layout(inner, user), origin=origin)


def h_cart_restore(req, sess, user, origin):
    blob = req.form.get("state") or (req.json().get("state") if req.raw_body else "")
    try:
        obj = pickle.loads(base64.b64decode(blob))   # VULN: insecure deserialization
        sess["cart"] = obj
        return resp(json.dumps({"restored": True}), ctype="application/json",
                    origin=origin)
    except Exception as ex:
        return resp(json.dumps({"error": str(ex)}), status=400,
                    ctype="application/json", origin=origin)


def h_reset_link(req, sess, user, origin):
    host = req.header("Host", "localhost")   # VULN: Host header injection
    return resp(json.dumps({"reset_url": f"http://{host}/reset?token=abc123"}),
                ctype="application/json", origin=origin)


def h_promo(req, sess, user, origin):
    xfh = req.header("X-Forwarded-Host", req.header("Host", "localhost"))
    # VULN: web cache poisoning via unkeyed X-Forwarded-Host reflected into cache
    body = (f'<div class="card">Promo! '
            f'<script src="http://{xfh}/promo.js"></script></div>')
    return resp(layout(body, user), origin=origin,
                extra={"Cache-Control": "public, max-age=60",
                       "X-Cache-Key": req.path})


def h_cache_deception(req, sess, user, origin):
    # VULN: web cache deception — secret JSON served & cached under a .css path
    return resp(json.dumps({"user": user["username"], "api_key": user["api_key"]}),
                ctype="application/json", origin=origin,
                extra={"Cache-Control": "public, max-age=300"})


def h_debug(req, sess, user, origin):
    # VULN: information disclosure
    return resp(json.dumps({
        "jwt_secret": JWT_SECRET, "db": DB_PATH, "cwd": os.getcwd(),
        "env": {k: os.environ.get(k) for k in list(os.environ)[:20]},
        "sessions": list(SESSIONS.keys()),
    }, indent=2), ctype="application/json", origin=origin)


def h_redeem(req, sess, user, origin):
    # VULN: race condition — read-modify-write without a lock, widened window
    conn = db()
    bal = conn.execute("SELECT balance FROM users WHERE id=?", (user["id"],)
                       ).fetchone()["balance"]
    time.sleep(0.03)
    conn.execute("UPDATE users SET balance=? WHERE id=?", (bal + 25, user["id"]))
    conn.commit()
    conn.close()
    return resp(json.dumps({"balance": bal + 25}), ctype="application/json",
                origin=origin)


def h_welcome(req, sess, user, origin):
    inner = """<div class="card"><h2>Welcome</h2><div id="out"></div>
      <script>
       /* VULN: DOM XSS — location.hash written to innerHTML */
       var n=decodeURIComponent(location.hash.slice(1));
       document.getElementById('out').innerHTML="Hi "+n;
      </script>
      <p class="muted">Try <code>/welcome#&lt;name&gt;</code>.</p></div>"""
    return resp(layout(inner, user), origin=origin)


def h_chat(req, sess, user, origin):
    conn = db()
    msgs = conn.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    rows = "".join(f'<div class="card"><b>{e(m["username"])}</b>: {m["body"]}</div>'
                   for m in msgs)   # VULN: stored XSS over chat channel
    inner = f"""<div class="card"><h2>Live chat</h2>
      <div class="row"><input id="m" placeholder="Message" style="flex:1">
      <button class="btn" onclick="snd()">Send</button></div></div>{rows}
      <script>
       function snd(){{var v=document.getElementById('m').value;
        fetch('/ws/send',{{method:'POST',headers:{{'Content-Type':'application/json'}},
        body:JSON.stringify({{body:v}})}}).then(()=>location.reload());}}
      </script>
      <p class="muted">A real WebSocket (/ws) upgrade with no Origin check lives
      in the Flask variant (src/app.py); here messages post over fetch.</p>"""
    return resp(layout(inner, user), origin=origin)


def h_ws_send(req, sess, user, origin):
    # VULN: no CSRF/origin check on chat control channel; stored XSS
    body = req.json().get("body", "")
    conn = db()
    conn.execute("INSERT INTO messages(username,body) VALUES(?,?)",
                 (user["username"], body))
    conn.commit()
    conn.close()
    return resp(json.dumps({"ok": True}), ctype="application/json", origin=origin)


def h_api_search(req, sess, user, origin):
    # Request-smuggling practice target (needs a vulnerable front proxy to exploit).
    return resp(json.dumps({
        "q": req.form.get("q", ""),
        "content_length": req.header("Content-Length"),
        "transfer_encoding": req.header("Transfer-Encoding"),
        "x_forwarded_for": req.header("X-Forwarded-For"),
    }), ctype="application/json", origin=origin)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

PUBLIC = {"/", "/login", "/logout", "/register", "/api/me", "/api/products",
          "/api/search", "/reset-link", "/promo", "/welcome", "/debug"}
PUBLIC_PREFIX = ("/api/user/",)


async def route(req, sess, user, origin):
    path, m = req.path, req.method

    # dynamic: /product/<id>, /api/user/<id>, cache deception *.css under /account/
    if path.startswith("/product/"):
        if not need_login(sess):
            return redirect("/login")
        try:
            pid = int(path.split("/")[2])
        except Exception:
            return resp(layout('<div class="card">Bad id</div>', user), status=404,
                        origin=origin)
        return h_product(req, sess, user, origin, pid)
    if path.startswith("/api/user/"):
        try:
            uid = int(path.split("/")[3])
        except Exception:
            return resp("{}", status=404, ctype="application/json", origin=origin)
        return h_api_user(req, sess, user, origin, uid)
    if path.startswith("/account/") and path.endswith(".css"):
        if not need_login(sess):
            return redirect("/login")
        return h_cache_deception(req, sess, user, origin)

    table = {
        "/": h_home, "/login": h_login, "/logout": h_logout, "/register": h_register,
        "/products": h_products, "/cart/add": h_cart_add, "/cart": h_cart,
        "/checkout": h_checkout, "/orders": h_orders, "/account": h_account,
        "/account/settings": h_settings, "/admin": h_admin, "/admin/exec": h_admin_exec,
        "/api/me": h_api_me, "/api/products": h_api_products, "/import": h_import,
        "/greet": h_greet, "/download": h_download, "/upload": h_upload,
        "/cart/restore": h_cart_restore, "/reset-link": h_reset_link,
        "/promo": h_promo, "/debug": h_debug, "/redeem": h_redeem,
        "/welcome": h_welcome, "/chat": h_chat, "/ws/send": h_ws_send,
        "/api/search": h_api_search,
    }
    if path == "/fetch":
        if not need_login(sess):
            return redirect("/login")
        return await h_fetch(req, sess, user, origin)

    handler = table.get(path)
    if handler is None:
        return resp(layout('<div class="card"><h2>404</h2>Page not found.</div>',
                           user), status=404, origin=origin)
    # auth gate: everything except the public set requires login
    if path not in PUBLIC and not any(path.startswith(p) for p in PUBLIC_PREFIX):
        if not need_login(sess):
            return redirect("/login")
    return handler(req, sess, user, origin)


# ---------------------------------------------------------------------------
# Worker entrypoint
# ---------------------------------------------------------------------------

class Default(WorkerEntrypoint):
    async def fetch(self, request):
        init_db()
        try:
            body_text = str(await request.text())
        except Exception:
            body_text = ""
        req = Req(request, body_text)
        origin = req.header("Origin")

        sid, sess = get_session(req)
        set_cookie = None
        if sess is None:
            sid = new_session()
            sess = SESSIONS[sid]
            set_cookie = f"sid={sid}; Path=/"

        user = current_user(sess)
        try:
            response = await route(req, sess, user, origin)
        except Exception as ex:
            # VULN: verbose error disclosure
            response = resp(f"<pre>Server error: {e(repr(ex))}</pre>", status=500,
                            origin=origin)

        if set_cookie:
            try:
                response.headers.append("Set-Cookie", set_cookie)
            except Exception:
                pass
        return response
