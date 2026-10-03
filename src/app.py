"""
ShopNow — intentionally vulnerable web-shop training lab.

FOR AUTHORIZED SECURITY TRAINING ONLY. Run locally / in an isolated
environment. DO NOT expose this to the public Internet. Every route here is
deliberately insecure so learners can practise exploitation.

Run:
    pip install flask
    python src/app.py
Then open http://127.0.0.1:8080  (login: admin / admin)
"""
import base64
import hashlib
import hmac
import json
import os
import pickle
import sqlite3
import subprocess
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for, make_response,
    render_template_string, jsonify, g, Response, send_file,
)

DB_PATH = os.environ.get("SHOP_DB", "/tmp/shopnow.sqlite3")
UPLOAD_DIR = os.environ.get("SHOP_UPLOADS", "/tmp/shopnow_uploads")
JWT_SECRET = "s3cr3t"          # weak, guessable on purpose
SECRET_KEY = "dev-not-secret"  # predictable Flask session key on purpose

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Idempotent schema + seed. Re-running keeps learner state."""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'customer',
            balance REAL DEFAULT 100.0,
            api_key TEXT,
            is_vip INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, description TEXT, price REAL,
            category TEXT, stock INTEGER DEFAULT 10, image TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER, product_id INTEGER, qty INTEGER,
            total REAL, status TEXT DEFAULT 'pending',
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER, author TEXT, body TEXT
        );
        CREATE TABLE IF NOT EXISTS coupons (
            code TEXT PRIMARY KEY, percent INTEGER
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, body TEXT
        );
        """
    )
    cur = db.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        db.execute(
            "INSERT INTO users(username,password,role,balance,api_key,is_vip)"
            " VALUES(?,?,?,?,?,?)",
            ("admin", "admin", "admin", 100000.0, "ADMIN-KEY-9931", 1),
        )
        db.execute(
            "INSERT INTO users(username,password,role,balance,api_key,is_vip)"
            " VALUES(?,?,?,?,?,?)",
            ("carlos", "montoya", "customer", 50.0, "CUST-KEY-1020", 0),
        )
    cur = db.execute("SELECT COUNT(*) AS c FROM products")
    if cur.fetchone()["c"] == 0:
        products = [
            ("Wireless Headphones", "Noise-cancelling over-ear headphones.",
             89.99, "audio", 25, "headphones.png"),
            ("Mechanical Keyboard", "RGB hot-swappable mechanical keyboard.",
             119.00, "accessories", 40, "keyboard.png"),
            ("4K Monitor", "27-inch 4K IPS display with USB-C.",
             349.50, "displays", 12, "monitor.png"),
            ("USB-C Charger", "65W GaN fast charger.",
             29.99, "accessories", 100, "charger.png"),
            ("Webcam Pro", "1080p webcam with privacy shutter.",
             54.00, "accessories", 30, "webcam.png"),
            ("Gaming Mouse", "16000 DPI ergonomic gaming mouse.",
             39.99, "accessories", 60, "mouse.png"),
            ("Leather Wallet", "Genuine leather RFID-blocking wallet.",
             24.99, "lifestyle", 80, "wallet.png"),
            ("Secret Prototype X1", "Internal only. Not for sale yet.",
             999999.0, "hidden", 1, "secret.png"),
        ]
        db.executemany(
            "INSERT INTO products(name,description,price,category,stock,image)"
            " VALUES(?,?,?,?,?,?)", products)
        db.executemany(
            "INSERT INTO reviews(product_id,author,body) VALUES(?,?,?)",
            [(1, "mike", "Great sound!"), (2, "lucy", "Love the switches.")])
        db.executemany("INSERT INTO coupons(code,percent) VALUES(?,?)",
                       [("WELCOME10", 10), ("VIP50", 50)])
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Auth helpers  (intentionally weak)
# ---------------------------------------------------------------------------

def current_user():
    uid = session.get("uid")
    if uid is None:
        return None
    row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return row


def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if session.get("uid") is None:
            return redirect(url_for("login"))
        return f(*a, **k)
    return wrapper


# -- hand-rolled JWT so alg:none / weak-secret issues are reachable ----------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url(json.dumps(header).encode())
    p = b64url(json.dumps(payload).encode())
    sig = hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(),
                   hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"


def jwt_decode(token: str):
    h, p, s = token.split(".")
    header = json.loads(b64url_dec(h))
    payload = json.loads(b64url_dec(p))
    alg = header.get("alg", "")
    if alg == "none":                       # VULN: accepts unsigned tokens
        return payload
    expected = b64url(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(),
                               hashlib.sha256).digest())
    if not hmac.compare_digest(expected, s):
        raise ValueError("bad signature")
    return payload


# ---------------------------------------------------------------------------
# Layout / templates
# ---------------------------------------------------------------------------

BASE = """
<!doctype html><html><head><title>ShopNow</title>
<style>
 body{font-family:system-ui,Arial;margin:0;background:#f4f5f7;color:#222}
 header{background:#1f2937;color:#fff;padding:12px 24px;display:flex;
   align-items:center;gap:24px}
 header a{color:#cbd5e1;text-decoration:none}
 .wrap{max-width:1000px;margin:24px auto;padding:0 16px}
 .card{background:#fff;border-radius:10px;padding:16px;margin:12px 0;
   box-shadow:0 1px 3px rgba(0,0,0,.1)}
 .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
 .btn{background:#2563eb;color:#fff;border:none;padding:8px 14px;
   border-radius:6px;cursor:pointer;text-decoration:none;display:inline-block}
 input,textarea,select{padding:8px;border:1px solid #cbd5e1;border-radius:6px;
   width:100%;box-sizing:border-box;margin:4px 0}
 .price{color:#059669;font-weight:700}
 .muted{color:#6b7280;font-size:13px}
</style></head><body>
<header>
 <a href="/" style="font-weight:700;color:#fff">ShopNow</a>
 <a href="/products">Shop</a><a href="/cart">Cart</a>
 <a href="/orders">Orders</a><a href="/account">Account</a>
 {% if user and user['role']=='admin' %}<a href="/admin">Admin</a>{% endif %}
 <span style="margin-left:auto"></span>
 {% if user %}<span class="muted" style="color:#9ca3af">{{user['username']}}</span>
   <a href="/logout">Logout</a>
 {% else %}<a href="/login">Login</a>{% endif %}
</header>
<div class="wrap">{{ body|safe }}</div>
</body></html>
"""


def page(body_html, **ctx):
    user = current_user()
    inner = render_template_string(body_html, user=user, **ctx)
    return render_template_string(BASE, body=inner, user=user)


# ---------------------------------------------------------------------------
# Home / auth
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    msg = request.args.get("msg", "Welcome to ShopNow!")   # VULN: reflected XSS
    body = """
      <div class="card"><h1>ShopNow</h1>
      <p>{{ m|safe }}</p>
      <p class="muted">Your one-stop electronics shop.</p>
      <a class="btn" href="/products">Browse products</a></div>
    """
    if current_user() is None:
        body = ("<div class='card'><h1>ShopNow</h1>"
                "<p>Please <a href='/login'>log in</a> to start shopping.</p>"
                "</div>")
        return page(body)
    return page(body, m=msg)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # VULN: SQL injection (string-formatted auth query)
        q = ("SELECT * FROM users WHERE username='%s' AND password='%s'"
             % (u, p))
        try:
            row = get_db().execute(q).fetchone()
        except Exception as e:
            row = None
            error = str(e)                       # VULN: info disclosure
        if row:
            session["uid"] = row["id"]
            session["role"] = row["role"]        # VULN: role trusted from here
            return redirect(url_for("home"))
        error = error or "Invalid credentials"
    body = """
      <div class="card" style="max-width:360px;margin:auto">
      <h2>Login</h2><p style="color:#b91c1c">{{err}}</p>
      <form method="post">
        <input name="username" placeholder="Username" autofocus>
        <input name="password" type="password" placeholder="Password">
        <button class="btn" type="submit">Sign in</button>
      </form>
      <p class="muted">Demo: admin / admin</p></div>
    """
    return page(body, err=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        role = request.form.get("role", "customer")   # VULN: mass assignment
        try:
            get_db().execute(
                "INSERT INTO users(username,password,role) VALUES(?,?,?)",
                (u, p, role))
            get_db().commit()
        except Exception as e:
            return page("<div class=card>%s</div>" % e)
        return redirect(url_for("login"))
    body = """
     <div class="card" style="max-width:360px;margin:auto"><h2>Register</h2>
     <form method="post">
       <input name="username" placeholder="Username">
       <input name="password" type="password" placeholder="Password">
       <button class="btn">Create account</button>
     </form></div>"""
    return page(body)


# ---------------------------------------------------------------------------
# Products / search  (SQLi + stored XSS via reviews)
# ---------------------------------------------------------------------------

@app.route("/products")
@login_required
def products():
    q = request.args.get("q")
    cat = request.args.get("category")
    sql = "SELECT * FROM products WHERE category!='hidden'"
    if q is not None:
        # VULN: SQL injection in search
        sql = ("SELECT * FROM products WHERE name LIKE '%%%s%%'"
               " OR description LIKE '%%%s%%'" % (q, q))
    elif cat:
        sql = "SELECT * FROM products WHERE category='%s'" % cat
    try:
        rows = get_db().execute(sql).fetchall()
    except Exception as e:
        return page("<div class=card>Query error: %s</div>" % e)   # info disc
    cards = "".join(
        f"""<div class="card"><h3>{r['name']}</h3>
            <p class="muted">{r['description']}</p>
            <p class="price">${r['price']:.2f}</p>
            <a class="btn" href="/product/{r['id']}">View</a></div>"""
        for r in rows)
    body = f"""
      <form method="get"><input name="q" placeholder="Search products..."
        value="{request.args.get('q','')}"></form>
      <div class="grid">{cards}</div>"""
    return page(body)


@app.route("/product/<int:pid>", methods=["GET", "POST"])
@login_required
def product(pid):
    db = get_db()
    if request.method == "POST":
        author = current_user()["username"]
        body = request.form.get("body", "")
        # VULN: stored XSS (review body rendered unescaped later)
        db.execute("INSERT INTO reviews(product_id,author,body) VALUES(?,?,?)",
                   (pid, author, body))
        db.commit()
    p = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p:
        return page("<div class=card>Not found</div>"), 404
    reviews = db.execute("SELECT * FROM reviews WHERE product_id=?",
                         (pid,)).fetchall()
    rev_html = "".join(
        f"<div class='card'><b>{r['author']}</b>: {r['body']}</div>"  # XSS
        for r in reviews)
    body = f"""
      <div class="card"><h2>{p['name']}</h2>
      <p>{p['description']}</p><p class="price">${p['price']:.2f}</p>
      <form method="post" action="/cart/add">
        <input type="hidden" name="product_id" value="{p['id']}">
        <input type="number" name="qty" value="1" style="width:80px">
        <button class="btn">Add to cart</button></form></div>
      <h3>Reviews</h3>{rev_html}
      <div class="card"><form method="post">
        <textarea name="body" placeholder="Write a review"></textarea>
        <button class="btn">Submit review</button></form></div>"""
    return page(body)


# ---------------------------------------------------------------------------
# Cart / checkout  (business logic + CSRF)
# ---------------------------------------------------------------------------

def get_cart():
    return session.setdefault("cart", {})


@app.route("/cart/add", methods=["POST"])
@login_required
def cart_add():
    pid = request.form.get("product_id")
    qty = int(request.form.get("qty", 1))     # VULN: negative qty allowed
    cart = get_cart()
    cart[pid] = cart.get(pid, 0) + qty
    session["cart"] = cart
    return redirect(url_for("cart"))


@app.route("/cart")
@login_required
def cart():
    db = get_db()
    rows = []
    total = 0
    for pid, qty in get_cart().items():
        p = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if p:
            line = p["price"] * qty
            total += line
            rows.append(f"<tr><td>{p['name']}</td><td>{qty}</td>"
                        f"<td>${line:.2f}</td></tr>")
    body = f"""
      <div class="card"><h2>Your cart</h2>
      <table width="100%">{''.join(rows)}</table>
      <p class="price">Total: ${total:.2f}</p>
      <!-- VULN: checkout has no CSRF token -->
      <form method="post" action="/checkout">
        <input name="coupon" placeholder="Coupon code">
        <button class="btn">Checkout</button></form></div>"""
    return page(body)


@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    db = get_db()
    user = current_user()
    coupon = request.form.get("coupon", "")
    total = 0
    for pid, qty in get_cart().items():
        p = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if p:
            total += p["price"] * qty          # negative qty lowers total
    percent = 0
    if coupon:
        c = db.execute("SELECT * FROM coupons WHERE code=?",
                       (coupon,)).fetchone()
        if c:
            percent = c["percent"]
    total = total * (100 - percent) / 100
    # VULN: no check that balance >= total, and total can be negative
    db.execute("UPDATE users SET balance=balance-? WHERE id=?",
               (total, user["id"]))
    db.execute(
        "INSERT INTO orders(user_id,product_id,qty,total,status,created_at)"
        " VALUES(?,?,?,?,?,?)",
        (user["id"], 0, 0, total, "paid", time.strftime("%Y-%m-%d %H:%M:%S")))
    db.commit()
    session["cart"] = {}
    return redirect(url_for("orders"))


@app.route("/orders")
@login_required
def orders():
    # VULN: IDOR via ?user_id= (access control)
    uid = request.args.get("user_id", session["uid"])
    rows = get_db().execute(
        "SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (uid,)
    ).fetchall()
    items = "".join(
        f"<div class='card'>Order #{r['id']} — ${r['total']:.2f} "
        f"[{r['status']}] {r['created_at']}</div>" for r in rows)
    return page(f"<h2>Orders</h2>{items or '<p>No orders.</p>'}")


# ---------------------------------------------------------------------------
# Account  (JWT cookie, prototype-pollution-style merge, SSRF avatar)
# ---------------------------------------------------------------------------

@app.route("/account")
@login_required
def account():
    user = current_user()
    token = jwt_encode({"sub": user["username"], "role": user["role"]})
    resp = make_response(page(f"""
      <div class="card"><h2>Account</h2>
      <p>User: {user['username']}</p><p>Role: {user['role']}</p>
      <p>Balance: ${user['balance']:.2f}</p>
      <p>API key: <code>{user['api_key']}</code></p>
      <p><a class="btn" href="/account/settings">Settings</a></p></div>"""))
    # VULN: session JWT with weak secret + alg:none accepted on /api/me
    resp.set_cookie("session_jwt", token)
    return resp


@app.route("/account/settings", methods=["GET", "POST"])
@login_required
def settings():
    prefs = session.get("prefs", {"theme": "light"})
    if request.method == "POST":
        try:
            incoming = json.loads(request.form.get("prefs", "{}"))
        except Exception:
            incoming = {}
        # VULN: recursive merge -> prototype-pollution-style gadget
        deep_merge(prefs, incoming)
        session["prefs"] = prefs
    body = f"""
      <div class="card"><h2>Settings</h2>
      <p>Current: <code>{json.dumps(prefs)}</code></p>
      <form method="post">
       <textarea name="prefs">{{"theme":"dark"}}</textarea>
       <button class="btn">Save (JSON)</button></form></div>"""
    if prefs.get("isAdmin"):     # gadget: pollution grants admin banner
        body += "<div class='card'>Admin mode unlocked via preferences.</div>"
    return page(body)


def deep_merge(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst


# ---------------------------------------------------------------------------
# Admin  (broken access control — only checks session role flag)
# ---------------------------------------------------------------------------

@app.route("/admin")
def admin():
    # VULN: relies on client-trusted session role; also reachable via JWT
    if session.get("role") != "admin":
        return page("<div class=card>Forbidden</div>"), 403
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    rows = "".join(f"<tr><td>{u['id']}</td><td>{u['username']}</td>"
                   f"<td>{u['role']}</td><td>${u['balance']:.2f}</td>"
                   f"<td>{u['api_key']}</td></tr>" for u in users)
    body = f"""
      <div class="card"><h2>Admin panel</h2>
      <table width="100%"><tr><th>ID</th><th>User</th><th>Role</th>
      <th>Balance</th><th>API key</th></tr>{rows}</table></div>
      <div class="card"><h3>Run maintenance ping</h3>
      <form method="post" action="/admin/ping">
       <input name="host" placeholder="host" value="127.0.0.1">
       <button class="btn">Ping</button></form></div>"""
    return page(body)


@app.route("/admin/ping", methods=["POST"])
def admin_ping():
    if session.get("role") != "admin":
        return "Forbidden", 403
    host = request.form.get("host", "")
    # VULN: OS command injection
    out = subprocess.run("ping -c 1 " + host, shell=True,
                         capture_output=True, text=True)
    return Response("<pre>%s%s</pre>" % (out.stdout, out.stderr),
                    mimetype="text/html")


# ---------------------------------------------------------------------------
# API surface  (JWT none, CORS, NoSQL-ish, access control)
# ---------------------------------------------------------------------------

@app.after_request
def add_headers(resp):
    # VULN: overly permissive CORS reflecting Origin + credentials
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    # VULN: no X-Frame-Options / CSP -> clickjacking & DOM sinks allowed
    return resp


@app.route("/api/me")
def api_me():
    token = (request.cookies.get("session_jwt")
             or request.headers.get("Authorization", "").replace("Bearer ", ""))
    if not token:
        return jsonify({"error": "no token"}), 401
    try:
        payload = jwt_decode(token)            # VULN: alg:none accepted
    except Exception as e:
        return jsonify({"error": str(e)}), 401
    return jsonify(payload)


@app.route("/api/products")
def api_products():
    # VULN: NoSQL-style filter object evaluated loosely + SQLi passthrough
    f = request.args.get("filter")
    sql = "SELECT * FROM products"
    if f:
        sql += " WHERE " + f      # VULN: raw filter injection
    try:
        rows = [dict(r) for r in get_db().execute(sql).fetchall()]
    except Exception as e:
        return jsonify({"error": str(e)}), 400     # info disclosure
    return jsonify(rows)


@app.route("/api/user/<int:uid>")
def api_user(uid):
    # VULN: no authz — any user record incl. api_key/password
    row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return jsonify(dict(row)) if row else (jsonify({}), 404)


# ---------------------------------------------------------------------------
# XXE / SSRF / SSTI / path traversal / deserialization / file upload
# ---------------------------------------------------------------------------

@app.route("/import", methods=["GET", "POST"])
@login_required
def import_xml():
    result = ""
    if request.method == "POST":
        data = request.form.get("xml") or request.data.decode("utf-8", "ignore")
        try:
            # VULN: XXE — external entities / DTD resolution enabled
            parser = ET.XMLParser()
            try:
                parser.parser.DefaultHandler = lambda d: None
            except Exception:
                pass
            root = ET.fromstring(data, parser=parser)
            result = ET.tostring(root, encoding="unicode")
        except Exception as e:
            result = str(e)
    body = f"""
      <div class="card"><h2>Import catalog (XML)</h2>
      <form method="post"><textarea name="xml" rows="8">
<catalog><item>sample</item></catalog></textarea>
      <button class="btn">Import</button></form>
      <pre>{result}</pre></div>"""
    return page(body)


@app.route("/fetch")
@login_required
def fetch_url():
    # VULN: SSRF — fetches any user-supplied URL incl. internal/metadata
    url = request.args.get("url", "")
    if not url:
        return page("<div class=card>Provide ?url=</div>")
    try:
        with urllib.request.urlopen(url, timeout=4) as r:
            data = r.read(4096).decode("utf-8", "ignore")
    except Exception as e:
        data = str(e)
    return Response("<pre>%s</pre>" % data, mimetype="text/html")


@app.route("/greet")
@login_required
def greet():
    # VULN: SSTI — user input rendered as a template
    name = request.args.get("name", "guest")
    tpl = "<div class='card'>Hello, %s!</div>" % name
    return page(render_template_string(tpl))


@app.route("/download")
@login_required
def download():
    # VULN: path traversal
    fname = request.args.get("file", "readme.txt")
    path = os.path.join(UPLOAD_DIR, fname)
    try:
        with open(path, "rb") as fh:
            return Response(fh.read(), mimetype="application/octet-stream")
    except Exception as e:
        return Response(str(e), status=404)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    msg = ""
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            # VULN: no type/extension validation, path from filename
            dest = os.path.join(UPLOAD_DIR, f.filename)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            f.save(dest)
            msg = "Saved to %s" % dest
    body = f"""
      <div class="card"><h2>Upload avatar</h2>
      <form method="post" enctype="multipart/form-data">
      <input type="file" name="file"><button class="btn">Upload</button></form>
      <p>{msg}</p></div>"""
    return page(body)


@app.route("/cart/restore", methods=["POST"])
@login_required
def cart_restore():
    # VULN: insecure deserialization of a base64 pickle blob
    blob = request.form.get("state", "")
    try:
        obj = pickle.loads(base64.b64decode(blob))
        session["cart"] = obj
        return jsonify({"restored": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Host header / cache poisoning / cache deception / info disclosure
# ---------------------------------------------------------------------------

@app.route("/reset-link")
def reset_link():
    # VULN: Host header injection into password-reset link
    host = request.headers.get("Host")
    return jsonify({"reset_url": f"http://{host}/reset?token=abc123"})


@app.route("/promo")
def promo():
    # VULN: web cache poisoning via unkeyed X-Forwarded-Host header
    xfh = request.headers.get("X-Forwarded-Host", request.host)
    resp = make_response(render_template_string(
        "<div class=card>Promo banner from "
        "<script src='http://{{h}}/promo.js'></script></div>", h=xfh))
    resp.headers["Cache-Control"] = "public, max-age=60"
    resp.headers["X-Cache-Key"] = request.path   # ignores the header -> poison
    return resp


@app.route("/account/<path:sub>.css")
@login_required
def cache_deception(sub):
    # VULN: web cache deception — sensitive data served under .css path
    user = current_user()
    resp = make_response(jsonify({"user": user["username"],
                                  "api_key": user["api_key"]}))
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


@app.route("/debug")
def debug():
    # VULN: information disclosure (env, config, source path)
    return jsonify({
        "env": dict(os.environ),
        "secret_key": SECRET_KEY,
        "jwt_secret": JWT_SECRET,
        "db": DB_PATH,
        "cwd": os.getcwd(),
    })


# ---------------------------------------------------------------------------
# Business logic / race condition  (coupon + balance)
# ---------------------------------------------------------------------------

@app.route("/redeem", methods=["POST"])
@login_required
def redeem():
    # VULN: race condition — read-modify-write without locking
    user = current_user()
    db = get_db()
    row = db.execute("SELECT balance FROM users WHERE id=?",
                     (user["id"],)).fetchone()
    bal = row["balance"]
    time.sleep(0.05)                 # widen the race window
    db.execute("UPDATE users SET balance=? WHERE id=?",
               (bal + 25, user["id"]))
    db.commit()
    return jsonify({"balance": bal + 25})


# ---------------------------------------------------------------------------
# DOM-based XSS  (client-side sink)
# ---------------------------------------------------------------------------

@app.route("/welcome")
def welcome():
    body = """
      <div class="card"><h2>Welcome</h2><div id="out"></div>
      <script>
        // VULN: DOM XSS — location.hash written to innerHTML
        var name = decodeURIComponent(location.hash.slice(1));
        document.getElementById('out').innerHTML = "Hi " + name;
      </script></div>"""
    return page(body)


# ---------------------------------------------------------------------------
# WebSocket-style chat (long-poll fallback; message stored unescaped -> XSS)
# ---------------------------------------------------------------------------

@app.route("/chat", methods=["GET"])
@login_required
def chat():
    msgs = get_db().execute(
        "SELECT * FROM messages ORDER BY id DESC LIMIT 20").fetchall()
    rows = "".join(f"<div class='card'><b>{m['username']}</b>: {m['body']}</div>"
                   for m in msgs)     # VULN: stored XSS over the chat channel
    body = f"""
      <div class="card"><h2>Live chat (WebSocket)</h2>
      <input id="m" placeholder="Message">
      <button class="btn" onclick="sendMsg()">Send</button></div>{rows}
      <script>
        var ws;
        try {{
          ws = new WebSocket((location.protocol=='https:'?'wss':'ws')
            + '://' + location.host + '/ws');
          ws.onmessage = function(e){{ document.title = e.data; }};
        }} catch(e) {{}}
        function sendMsg(){{
          var v=document.getElementById('m').value;
          if(ws && ws.readyState==1){{ ws.send(v); }}
          fetch('/ws/send',{{method:'POST',headers:
            {{'Content-Type':'application/json'}},
            body:JSON.stringify({{body:v}})}}).then(()=>location.reload());
        }}
      </script>"""
    return page(body)


@app.route("/ws/send", methods=["POST"])
@login_required
def ws_send():
    # VULN: no origin/CSRF check on the WebSocket control channel; stored XSS
    data = request.get_json(silent=True) or {}
    body = data.get("body", "")
    db = get_db()
    db.execute("INSERT INTO messages(username,body) VALUES(?,?)",
               (current_user()["username"], body))
    db.commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# HTTP request smuggling note endpoint (documented; needs a front proxy)
# ---------------------------------------------------------------------------

@app.route("/api/search", methods=["POST"])
def api_search():
    # Request-smuggling practice target: trusts X-Forwarded-For blindly and
    # mixes framing-sensitive headers. Real smuggling requires a vulnerable
    # front-end proxy in front of this app (documented in README).
    cl = request.headers.get("Content-Length")
    te = request.headers.get("Transfer-Encoding")
    return jsonify({"q": request.form.get("q", ""),
                    "cl": cl, "te": te,
                    "xff": request.headers.get("X-Forwarded-For")})


# ---------------------------------------------------------------------------
# WebSocket endpoint (optional, only if flask-sock is installed)
# ---------------------------------------------------------------------------
try:
    from flask_sock import Sock
    sock = Sock(app)

    @sock.route("/ws")
    def ws(ws):                       # VULN: no origin check -> cross-site WS
        while True:
            msg = ws.receive()
            if msg is None:
                break
            db = sqlite3.connect(DB_PATH)
            db.execute("INSERT INTO messages(username,body) VALUES(?,?)",
                       ("ws-guest", msg))
            db.commit(); db.close()
            ws.send("new message: " + msg)
except Exception:
    pass  # WebSocket upgrade falls back to the /ws/send long-poll route


if __name__ == "__main__":
    init_db()
    # Bind to localhost by default — do NOT expose this lab publicly.
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "8080")), debug=True,
            threaded=True)
