# ShopNow — Vulnerable Web-Shop Training Lab

> ⚠️ **FOR AUTHORIZED SECURITY TRAINING ONLY.**
> Every endpoint here is deliberately insecure. Run it **locally / isolated**.
> **Never expose it to the public Internet.** No real secrets or data are used.

A realistic-looking production-style electronics shop (catalog, cart,
checkout, orders, account, admin, chat, API) that is riddled with intentional
vulnerabilities for hands-on exploitation practice. The UI gives **no hints**
that anything is vulnerable — finding the bugs is the exercise.

There are **two variants of the same lab**, same credentials and behaviour:

1. **`src/worker.py` — Cloudflare Python Worker** (recommended; runs on
   Cloudflare). Pure-Python, no external packages.
2. **`src/app.py` — plain Flask app** (for any host). Adds a few vulns that a
   serverless sandbox cannot host (real OS command injection via `subprocess`,
   `lxml`-style XXE, a true WebSocket `/ws` with no origin check).

### Run on Cloudflare (Workers / `wrangler`)

The Python Workers runtime needs the `workers-py` SDK bundled, which is done by
**pywrangler** (plain `npx wrangler dev` alone will fail with
`No module named 'flask'`/`'workers'` — use pywrangler):

```bash
# requires uv >= 0.12.3  (pip install --upgrade uv)
uvx --from workers-py pywrangler dev          # local dev  -> http://localhost:8787
uvx --from workers-py pywrangler deploy       # deploy to Cloudflare
```

Verified running under `pywrangler dev`: login `admin:admin`, SQLi login
bypass, JWT `alg:none`, SSTI (`/greet?name={{7*7}}`), IDOR, `/debug` disclosure.

Notes for the Workers runtime:
- SQLite lives at `/tmp/shopnow.sqlite3` on Pyodide's in-memory filesystem and
  is re-seeded per isolate (idempotent). Sessions/cart are kept in-memory.
- OS command injection is realised as server-side **code injection** (`eval`)
  at `/admin/exec`, because the sandbox has no OS shell. The `subprocess`-based
  OS command injection lives in the Flask variant.
- Do **not** keep `requirements.txt` in the repo root — pywrangler reads deps
  from `pyproject.toml`; Flask-variant deps live in `requirements-fulllab.txt`.

### Run the Flask variant (any host)

```bash
pip install -r requirements-fulllab.txt
python src/app.py                             # -> http://127.0.0.1:8080
```

Env overrides (Flask variant): `PORT`, `HOST`, `SHOP_DB`, `SHOP_UPLOADS`.

### Common to both

- **Login (hardcoded, cannot be changed): `admin` / `admin`**
- Second seeded user: `carlos` / `montoya` (low privilege)
- Seeded **products** table (incl. a hidden one) for injection practice.
- **You must log in first**; shop/exploit surfaces are gated behind auth.

## Vulnerability map (no hints shown in the UI)

| Class | Where to look |
|---|---|
| SQL injection | `POST /login`, `GET /products?q=`, `GET /api/products?filter=` |
| Cross-site scripting (reflected) | `GET /?msg=` |
| Stored XSS | product reviews `/product/<id>`, chat `/chat` |
| DOM-based XSS | `GET /welcome#<payload>` (location.hash → innerHTML) |
| CSRF | `POST /checkout`, `POST /ws/send` (no token/origin check) |
| Clickjacking | no `X-Frame-Options`/CSP anywhere (frame any page) |
| CORS misconfiguration | reflected `Origin` + `Allow-Credentials: true` on `/api/*` |
| XXE | `POST /import` (XML parsed with entity resolution) |
| SSRF | `GET /fetch?url=` (fetches arbitrary/internal URLs) |
| HTTP request smuggling | `POST /api/search` (trusts CL/TE/XFF; needs a vuln front proxy) |
| OS command injection | Flask: `POST /admin/ping` (`host` → shell). Worker: `POST /admin/exec` (server-side code injection — no OS in sandbox) |
| SSTI | `GET /greet?name=` (input rendered as a Jinja template) |
| Path traversal | `GET /download?file=../../etc/passwd` |
| Access control / IDOR | `GET /orders?user_id=`, `GET /api/user/<id>`, `/admin` |
| Authentication | SQLi login bypass, predictable session key, `/register` role field |
| WebSockets | `/ws` (no origin check) + `/ws/send` long-poll fallback |
| Web cache poisoning | `GET /promo` (unkeyed `X-Forwarded-Host` in cached response) |
| Web cache deception | `GET /account/<anything>.css` (secret JSON cached under .css) |
| Insecure deserialization | `POST /cart/restore` (base64 pickle `state`) |
| Information disclosure | `GET /debug`, verbose SQL errors on query pages |
| Business logic | negative cart `qty`, coupon stacking, no balance check at checkout |
| HTTP Host header attacks | `GET /reset-link` (Host header → password reset URL) |
| File upload | `POST /upload` (no type/ext validation, filename path) |
| JWT | `GET /api/me` (accepts `alg:none` and weak `HS256` secret `s3cr3t`) |
| Prototype-pollution-style | `POST /account/settings` (recursive merge → `isAdmin` gadget) |
| Race conditions | `POST /redeem` (read-modify-write balance, widened window) |
| NoSQL-style injection | `GET /api/products?filter=` (raw filter object/clause) |
| API testing | `/api/me`, `/api/products`, `/api/user/<id>`, `/api/search` |

## Quick exploitation starters (examples)

- SQLi login bypass: username `admin'-- -`, any password.
- UNION SQLi: `/products?q=x' UNION SELECT 1,username,password,4,5,6,7 FROM users-- -`
- SSTI: `/greet?name={{7*7}}`
- Path traversal: `/download?file=../../etc/passwd`
- JWT none: send `Authorization: Bearer <alg:none>.<{"role":"admin"}>.`
- DOM XSS: `/welcome#<img src=x onerror=alert(1)>`
- SSRF: `/fetch?url=http://127.0.0.1:8080/debug`

These are starting points for authorized practice; discovering the rest is
part of the exercise.
