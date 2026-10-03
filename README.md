# Cloudflare-Pages (my-flask-worker)

A minimal **Flask** application running on **Cloudflare Workers** using
Cloudflare's Python Workers runtime (`workers-py`). Instead of a static
Cloudflare Pages site, this project runs Python server-side code at the edge.

> Naming note: the GitHub repository is named `Cloudflare-Pages` (hosting
> name, unrelated to code), while the canonical Worker/package name is
> `my-flask-worker`, as declared consistently in `pyproject.toml` and
> `wrangler.jsonc`. This was a deliberate decision — see the Architecture
> Decision Log in [NOTE.md](./NOTE.md) for details.

## Features

- Flask app served through Cloudflare's Python Workers (Pyodide-based) via
  the `workers-py` WSGI adapter.
- Single endpoint: `GET /` → returns `{"message": "Hello from Flask"}`.

## Project Structure

```
.
├── src/
│   └── worker.py             # Flask app + Cloudflare Workers WSGI entrypoint
├── tests/
│   ├── conftest.py            # Stubs the `workers` module for local testing
│   └── test_worker.py         # Pytest test suite for the Flask app
├── .github/workflows/ci.yml   # CI: runs pytest on push/PR
├── pyproject.toml              # Python project metadata & dependencies
├── wrangler.jsonc               # Cloudflare Workers configuration
├── NOTE.md                       # Project memory / documentation
├── docs/changelog/                # Dated changelog entries
└── README.md
```

## Prerequisites

- [Python](https://www.python.org/) >= 3.13
- [Node.js](https://nodejs.org/) + [npm](https://www.npmjs.com/) (required to
  run the [Wrangler](https://developers.cloudflare.com/workers/wrangler/) CLI)
- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (for `wrangler login` / deployment)
- [uv](https://docs.astral.sh/uv/) or `pip` to manage the Python dependencies
  declared in `pyproject.toml`

## Setup

1. Install Python dependencies (using [uv](https://docs.astral.sh/uv/), or
   substitute your preferred tool):

   ```bash
   uv sync
   ```

   or with `pip`:

   ```bash
   pip install flask workers-py workers-runtime-sdk
   ```

2. Install Wrangler (via npx, no global install required):

   ```bash
   npx wrangler --version
   ```

## Local Development

Run the worker locally with Wrangler's dev server:

```bash
npx wrangler dev
```

This starts a local server (by default at `http://localhost:8787`) that
serves the Flask app defined in `src/worker.py`. Open `/` in your browser or
call it with curl:

```bash
curl http://localhost:8787/
# {"message": "Hello from Flask"}
```

## Testing

Automated tests live in `tests/` and use `pytest` + Flask's test client.
Since Cloudflare's `workers` package (`workers-py`) only exists inside the
Cloudflare Workers Python runtime, `tests/conftest.py` stubs it out so
`src/worker.py` can be imported and tested locally/in CI.

```bash
pip install flask pytest   # or: uv sync
pytest
```

Continuous integration runs the same test suite on every push/PR via
GitHub Actions (see `.github/workflows/ci.yml`).

## Deployment

### Manual deploy (Wrangler CLI)

Authenticate with Cloudflare (one-time):

```bash
npx wrangler login
```

Deploy the Worker:

```bash
npx wrangler deploy
```

### Git-connected deploy (Cloudflare dashboard)

If this repo is connected to Cloudflare (Workers & Pages → project →
Settings → Build), the following Build configuration is used to
build/deploy automatically on push:

| Setting | Value |
|---|---|
| Build command | `uvx --from workers-py pywrangler deploy` |
| Deploy command | `npx wrangler deploy` |
| Version command | `npx wrangler versions upload` |
| Root directory | `/` |

The Build command runs `pywrangler deploy` (from the `workers-py`
package, via `uvx`) to handle Python-Worker-specific bundling before
Wrangler deploys. The Deploy command runs on the production branch; the
Version command runs on preview/non-production branches (uploads a new
version without making it live — Cloudflare's Gradual/Preview
Deployments workflow).

## Configuration

Worker settings live in `wrangler.jsonc`:

- `main`: `src/worker.py` — the Worker's entry point.
- `compatibility_flags`: `["python_workers"]` — enables the Python Workers
  runtime.
- `compatibility_date` — the Workers runtime compatibility date.

## Status & Roadmap

This is an early-stage starter project. See [NOTE.md](./NOTE.md) for the full
project memory, architecture decisions, current state, and pending issues
(e.g. naming cleanup, missing tests/CI). Daily change history is tracked in
[docs/changelog/](./docs/changelog/).
