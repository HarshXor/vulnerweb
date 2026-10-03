"""Pytest config: stub Cloudflare's `workers` package.

The `workers` runtime bindings only exist inside the Cloudflare Workers
Python (Pyodide) sandbox and cannot be pip-installed locally/CI. We stub a
minimal `WorkerEntrypoint` and `Response` so `src/worker.py` imports and its
pure-Python logic (DB seeding, JWT, merge, routing helpers) can be tested
outside that sandbox.
"""
import sys
import types

if "workers" not in sys.modules:
    workers_module = types.ModuleType("workers")

    class WorkerEntrypoint:  # minimal base
        def __init__(self, *a, **k):
            pass

    class Response:
        def __init__(self, body="", status=200, headers=None):
            self.body = body
            self.status = status
            self.headers = headers or {}

    workers_module.WorkerEntrypoint = WorkerEntrypoint
    workers_module.Response = Response
    # legacy wsgi stub (kept for any older imports)
    wsgi_module = types.ModuleType("workers.wsgi")
    wsgi_module.entrypoint = lambda app: app
    workers_module.wsgi = wsgi_module
    sys.modules["workers"] = workers_module
    sys.modules["workers.wsgi"] = wsgi_module
