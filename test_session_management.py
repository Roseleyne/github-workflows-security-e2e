"""
A5 - Gestao de sessao e fluxo de logout/refresh.
Cobre: invalidacao de token apos logout e cookies de sessao seguros (web).
"""
import pytest


def test_token_invalidated_after_logout(user_a):
    """Apos logout, o token anterior nao deve mais funcionar."""
    pre = user_a.get("/api/v1/users/me")
    assert pre.status_code == 200, "Pre-condicao: token valido"
    user_a.post("/auth/logout")
    post = user_a.get("/api/v1/users/me")
    assert post.status_code == 401, \
        f"Token continua valido apos logout (HTTP {post.status_code})"


def test_session_cookie_flags_web(anon):
    """Cookie de sessao web deve ter HttpOnly, Secure e SameSite."""
    from conftest import APP
    r = anon.s.post(f"{APP}/login",
                    data={"email": "usera@test.local", "password": "Passw0rd!A"},
                    timeout=15)
    set_cookie = r.headers.get("Set-Cookie", "")
    if not set_cookie:
        pytest.skip("Login web nao retornou Set-Cookie")
    low = set_cookie.lower()
    assert "httponly" in low, "Cookie sem HttpOnly"
    assert "secure" in low, "Cookie sem Secure"
    assert "samesite" in low, "Cookie sem SameSite"
