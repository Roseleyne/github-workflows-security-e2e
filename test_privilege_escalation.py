"""
A3 - Escalonamento de privilegio (vertical e horizontal).
Broken Function Level Authorization (API5:2023) + A01 Broken Access Control.
"""
import pytest

ADMIN_ENDPOINTS = [
    ("GET", "/api/v1/admin/users"),
    ("GET", "/api/v1/admin/audit-logs"),
    ("POST", "/api/v1/admin/users"),
    ("DELETE", "/api/v1/admin/users/1"),
    ("PUT", "/api/v1/admin/settings"),
]


@pytest.mark.parametrize("method,path", ADMIN_ENDPOINTS)
def test_vertical_escalation_blocked(user_a, method, path):
    """Usuario comum NAO deve acessar funcoes administrativas."""
    r = user_a.request(method, path, json={})
    assert r.status_code in (401, 403), \
        f"Escalonamento vertical: user comum acessou {method} {path} (HTTP {r.status_code})"


def test_role_tampering_on_self_update_blocked(user_a):
    """Usuario nao deve elevar o proprio papel via mass assignment."""
    r = user_a.put(f"/api/v1/users/{user_a.user_id}",
                   json={"role": "admin", "is_admin": True})
    if r.status_code in (200, 204):
        check = user_a.get("/api/v1/users/me").json()
        assert check.get("role") != "admin" and not check.get("is_admin"), \
            "Mass assignment permitiu auto-promocao a admin"


def test_forced_browsing_admin_panel_web(anon):
    """Acesso direto a area admin do front sem sessao deve ser barrado."""
    from conftest import APP
    r = anon.s.get(f"{APP}/admin", allow_redirects=False, timeout=15)
    assert r.status_code in (301, 302, 401, 403), \
        f"Forced browsing: /admin acessivel sem auth (HTTP {r.status_code})"


def test_horizontal_escalation_via_account_param(user_a, user_b):
    """user_a nao deve operar em nome de user_b passando account_id alheio."""
    r = user_a.post("/api/v1/transfers",
                    json={"from_account": user_b.user_id, "amount": 1, "to": "x"})
    assert r.status_code in (400, 403, 404), \
        f"Escalonamento horizontal aceito (HTTP {r.status_code})"
