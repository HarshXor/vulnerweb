# Cloudflare-Pages (my-flask-worker)

---

Project Start Date: 2026-09-13 (first commit `ed64735`)
Last Update Project: 2026-09-13 (all pending issues resolved; Cloudflare Pages/Workers build configuration confirmed & documented)
Project Phase: Initial Setup / Bootstrap
Project Status: Active — Development

---

## Project Summary

A minimal Flask application deployed as a Cloudflare Worker using Cloudflare's
Python Workers runtime (`workers-py`). The repository name is
"Cloudflare-Pages" but the actual package/worker is named `my-flask-worker`
(see `pyproject.toml` and `wrangler.jsonc`). Currently the app exposes a single
`GET /` route that returns a JSON greeting (`{"message": "Hello from Flask"}`).
This is a starter/proof-of-concept project for running Python (Flask) on
Cloudflare Workers rather than a traditional Cloudflare Pages static site.

## Mandatory Workflow

- First step for every task: always read NOTE.md before making changes.
- Check existing documentation before modifying architecture.
- Preserve existing project conventions.
- Last step for every task: always update NOTE.md and docs/changelog/[yyyy]/[mm]/[dd].md.

## Restrictions

- Do not modify core architecture without documentation.
- Do not remove existing features without confirmation.
- Do not introduce dependency without justification.
- Do not ignore existing project constraints.

## AI Operating Context

- AI acts as development assistant for this Flask-on-Cloudflare-Workers project.
- AI must prioritize consistency over speed.
- AI must document important decisions in this file and in the changelog.
- AI should keep the project minimal and avoid adding unnecessary tooling
  (build systems, frameworks) unless explicitly requested.
- AI must verify compatibility with the Cloudflare Python Workers runtime
  (`python_workers` compatibility flag) before introducing new dependencies,
  since not all Python packages are supported in that runtime (Pyodide-based).

## Technical Development Details

- **Programming language:** Python (>= 3.13, per `pyproject.toml`).
- **Framework:** Flask, adapted to run on Cloudflare Workers via the
  `workers-py` WSGI adapter (`workers.wsgi.entrypoint`).
- **Infrastructure:** Cloudflare Workers (Python Workers beta,
  `compatibility_flags: ["python_workers"]`, `compatibility_date: 2026-09-13`).
  Configured via `wrangler.jsonc` (Wrangler CLI, referenced schema at
  `node_modules/wrangler/config-schema.json` — Node/Wrangler tooling expected
  but `node_modules`/`package.json` are not currently committed; TBD — confirm
  with maintainer whether a Node/Wrangler install step is documented elsewhere).
- **Database:** None currently. No persistence layer configured.
- **API structure:** Single Flask route, `GET /` → returns JSON
  `{"message": "Hello from Flask"}`. No other routes exist yet.
- **Deployment model:** Cloudflare Workers, deployed via the Cloudflare
  dashboard's Git integration (Workers & Pages → project → Settings →
  Build). **Confirmed Build configuration (2026-09-13):**

  | Setting | Value |
  |---|---|
  | Build command | `uvx --from workers-py pywrangler deploy` |
  | Deploy command | `npx wrangler deploy` |
  | Version command | `npx wrangler versions upload` |
  | Root directory | `/` |

  Build command uses `uvx` to run `pywrangler deploy` from the `workers-py`
  package (handles Python-Worker-specific bundling, e.g. Pyodide
  packaging) before Wrangler deploys. Deploy command (`wrangler deploy`)
  runs on the production branch; Version command (`wrangler versions
  upload`) runs for preview/non-production branches (Cloudflare Workers
  Gradual/Preview Deployments), uploading a version without making it
  live. Root directory `/` = source lives at repo root (no monorepo
  subfolder). Manual/local equivalent: `npx wrangler login` then
  `npx wrangler deploy`; local dev via `npx wrangler dev`. Entry point is
  `src/worker.py` (see `wrangler.jsonc` → `"main": "src/worker.py"`).
- **Coding convention:** No linter/formatter config committed yet (no
  `.flake8`, `ruff.toml`, `pyproject` tool sections, etc.). TBD — confirm
  with maintainer if a style guide should be adopted.
- **Security requirement:** None documented yet. TBD — confirm with
  maintainer (e.g. CORS, auth, secrets handling via Wrangler `vars`/`secrets`).

## Core Flow Project

- **Input:** HTTP request to the Cloudflare Worker (e.g. `GET /`).
- **Processing:** Cloudflare Workers Python runtime loads `src/worker.py`,
  which builds a Flask `app` and wraps it with `workers.wsgi.entrypoint(app)`
  as the `Default` export, so Flask's WSGI request handling processes the
  incoming request.
- **Logic:** Flask route `index()` handles `GET /` and returns a JSON payload.
- **Output:** JSON response `{"message": "Hello from Flask"}`.
- **External integration:** None yet. Runtime dependency on Cloudflare's
  Python Workers platform (Pyodide-based) and the `workers-py` /
  `workers-runtime-sdk` packages (dev dependencies in `pyproject.toml`).

## Architecture Decision Log

Date: 2026-09-13
Decision: Use Flask + `workers-py` WSGI adapter to run a Python web app on
Cloudflare Workers, instead of a native Cloudflare Pages static site or a
JS/TS Worker.
Reason: Leverage familiar Flask routing/development model while targeting
Cloudflare's edge compute (Python Workers, currently in beta).
Impact: Project is constrained by the Python Workers runtime's supported
package set (Pyodide-based sandbox); not all PyPI packages will work.
Deployment relies on Wrangler and the `python_workers` compatibility flag.

Date: 2026-09-13
Decision: Standardize on `my-flask-worker` as the canonical Worker/package
name (in `pyproject.toml` and `wrangler.jsonc`); keep the GitHub repository
name `Cloudflare-Pages` as-is (a hosting-level setting, out of scope for
code changes) and document the distinction in README.md instead of trying
to force the two to match.
Reason: Git history shows the maintainer briefly renamed the worker to
`cloudflare-pages` (commit `ede00b2`) then deliberately reverted it back to
`my-flask-worker` (commit `84c0516`), indicating `my-flask-worker` is the
intended name. Renaming the GitHub repository itself is a hosting action,
not a file change, and is left to the maintainer if desired.
Impact: `pyproject.toml` and `wrangler.jsonc` remain internally consistent
(`my-flask-worker`); README.md explicitly explains the repo-name vs.
package-name distinction so it no longer reads as an unresolved bug.

Date: 2026-09-13
Decision: Add an automated test suite (`tests/`, pytest) and a GitHub
Actions CI workflow (`.github/workflows/ci.yml`), and stub Cloudflare's
`workers` module in `tests/conftest.py` rather than modifying
`src/worker.py`.
Reason: `workers-py` is only available inside the Cloudflare Workers Python
(Pyodide) runtime and can't be `pip install`ed locally/in CI, so
`src/worker.py` can't be imported as-is outside that sandbox. Stubbing the
module in test setup (instead of restructuring `worker.py` into separate
"app" vs. "entrypoint" modules) keeps the production code untouched while
still allowing the Flask `app` to be exercised with Flask's test client.
Impact: `pytest` added as a dev dependency; `[tool.pytest.ini_options]`
added to `pyproject.toml` (`pythonpath = ["src"]`, `testpaths = ["tests"]`).
CI now runs `pytest` on every push/PR to `main`.

## Current State

- Repository contains a minimal working skeleton: `src/worker.py` (Flask app
  + Workers WSGI entrypoint), `pyproject.toml` (deps: `flask`; dev deps:
  `workers-py`, `workers-runtime-sdk`), and `wrangler.jsonc` (Worker config).
- Only one endpoint exists (`GET /`) returning a static JSON message.
- Automated tests now exist: `tests/test_worker.py` (3 tests covering the
  `GET /` route, a 404 for unknown routes, and the `Default` WSGI export),
  with `tests/conftest.py` stubbing the `workers` module so tests run
  without the Cloudflare Workers Python runtime. Verified locally with
  `python3 -m pytest -q` → `3 passed`.
- CI added: `.github/workflows/ci.yml` runs `pytest` on every push/PR to
  `main` (installs `flask` + `pytest` via pip, Python 3.13).
- `pyproject.toml` updated: `pytest` added to `dev` dependency group;
  `[tool.pytest.ini_options]` added (`pythonpath = ["src"]`,
  `testpaths = ["tests"]`).
- No linting/formatting configuration is present yet (not required by any
  pending issue; still TBD if the maintainer wants one).
- `README.md` has been expanded (2026-09-13) from a bare title into a full
  guide: project description, naming-decision note, prerequisites
  (Python 3.13+, Node/npm for Wrangler), setup (`uv sync`/`pip`), local dev
  (`wrangler dev`), testing (`pytest`), deployment (`wrangler login` /
  `wrangler deploy`), config overview, and links to `NOTE.md` /
  `docs/changelog/`.
- Naming: `pyproject.toml` and `wrangler.jsonc` both consistently use
  `my-flask-worker` as the canonical Worker/package name (see Architecture
  Decision Log). The GitHub repository name `Cloudflare-Pages` is a
  hosting-level setting and intentionally left unchanged; README.md now
  explains the distinction explicitly.
- Working tree is clean; local `main` branch is up to date with `origin/main`.

## Cloudflare-runnable Worker variant (updated 2026-10-03)

- `src/worker.py` was rewritten from the Flask hello-world into a self-contained
  pure-Python **Cloudflare Python Worker** version of the ShopNow vulnerable lab
  (uses the `workers-py` SDK: `from workers import WorkerEntrypoint, Response`).
  It genuinely runs on the Cloudflare Workers runtime.
- Run with pywrangler (plain `npx wrangler dev` fails — it does not bundle the
  `workers-py`/flask Pyodide packages):
  `uvx --from workers-py pywrangler dev` (local) / `... pywrangler deploy`.
  Requires `uv >= 0.12.3`. `requirements.txt` must NOT exist in repo root or
  pywrangler aborts — Flask-variant deps moved to `requirements-fulllab.txt`;
  `pyproject.toml` dependencies set to `[]` (Worker is stdlib-only).
- SQLite at `/tmp/shopnow.sqlite3` on Pyodide MEMFS (re-seeded per isolate);
  sessions/cart in-memory. OS command injection is realised as code injection
  (`/admin/exec`, eval) since the sandbox has no shell; `subprocess`-based OS
  cmd injection stays in the Flask variant (`src/app.py`).
- Verified LIVE under `pywrangler dev`: GET / 200, admin:admin login (302),
  product listing, SQLi login bypass, JWT alg:none → {"role":"admin"}, SSTI
  /greet?name={{7*7}} → Hello, 49!, IDOR /api/user/1 leaks api_key, /debug
  discloses jwt_secret. Unit tests (tests/test_worker.py, workers stub in
  conftest) pass: 5 passed.

## Vulnerable Training Lab (added 2026-10-03)

- `src/app.py` is a standalone, intentionally vulnerable Flask "ShopNow"
  web-shop lab for **authorized security training only** (isolated/local,
  not for public exposure). It is independent of the Cloudflare Workers
  skeleton (`src/worker.py`), which is left untouched.
- SQLite DB at `/tmp/shopnow.sqlite3` (idempotent schema + seed); uploads at
  `/tmp/shopnow_uploads`. Hardcoded login `admin:admin` (also seeds `carlos`).
- Auth-gated shop flow (catalog/cart/checkout/orders/account/admin/chat/API).
- Covers all requested vuln classes (SQLi, XSS reflected/stored/DOM, CSRF,
  clickjacking, CORS, XXE, SSRF, OS cmd injection, SSTI, path traversal,
  access control/IDOR, auth, WebSockets, cache poisoning/deception, insecure
  deserialization, info disclosure, business logic, Host header, file upload,
  JWT alg:none/weak secret, prototype-pollution-style merge, race conditions,
  NoSQL-style/API testing). Request smuggling target documented (needs a
  vulnerable front proxy). Mapping + run steps in `README_LAB.md`.
- Run: `pip install -r requirements.txt && python src/app.py` → `:8080`.
- Verified: `py_compile` clean; smoke-tested auth gate, admin login, SQLi
  login bypass + UNION dump, JWT alg:none, `/debug` disclosure.

## Pending Issue

-

## Changelog Reference

See `docs/changelog/` for dated entries, organized as
`docs/changelog/[yyyy]/[mm]/[dd].md`. First entry: `docs/changelog/2026/09/13.md`.
