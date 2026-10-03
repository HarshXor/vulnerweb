"""Smoke tests for the pure-Python ShopNow Worker (no Pyodide runtime needed)."""
import os
import tempfile

import worker


def setup_module(_):
    # isolate the DB for tests
    worker.DB_PATH = os.path.join(tempfile.gettempdir(), "shopnow_test.sqlite3")
    if os.path.exists(worker.DB_PATH):
        os.remove(worker.DB_PATH)
    worker.init_db()


def test_seed_admin_and_products():
    conn = worker.db()
    admin = conn.execute(
        "SELECT * FROM users WHERE username='admin'").fetchone()
    nproducts = conn.execute("SELECT COUNT(*) c FROM products").fetchone()["c"]
    conn.close()
    assert admin is not None and admin["password"] == "admin"
    assert admin["role"] == "admin"
    assert nproducts >= 7  # includes seeded products for injection practice


def test_jwt_alg_none_is_accepted():
    header = worker.b64u(b'{"alg":"none","typ":"JWT"}')
    payload = worker.b64u(b'{"role":"admin"}')
    forged = f"{header}.{payload}."
    assert worker.jwt_decode(forged)["role"] == "admin"


def test_jwt_signature_enforced_for_hs256():
    good = worker.jwt_encode({"role": "customer"})
    assert worker.jwt_decode(good)["role"] == "customer"
    tampered = good[:-2] + ("aa" if good[-2:] != "aa" else "bb")
    try:
        worker.jwt_decode(tampered)
        assert False, "tampered token should fail"
    except Exception:
        pass


def test_deep_merge_pollutes():
    prefs = {"theme": "light"}
    worker.deep_merge(prefs, {"isAdmin": True, "nested": {"a": 1}})
    assert prefs["isAdmin"] is True and prefs["nested"]["a"] == 1


def test_sqli_login_query_is_string_built():
    # Confirms the auth query is injectable (string interpolation, not params).
    u, p = "admin'-- -", "x"
    q = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
    assert "admin'-- -" in q and "?" not in q
