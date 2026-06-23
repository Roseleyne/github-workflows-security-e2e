"""
A1 - Testes de AUTENTICACAO (AuthN).

Cobre: ausencia de credencial, token invalido/expirado, brute force / rate
limit, e enumeracao de usuario via mensagens de erro distintas.
Mapeado a OWASP ASVS V2 e API2:2023 (Broken Authentication).
"""
import time
import jwt
import pytest


PROTECTED = "/api/v1/users/me"


def test_no_token_is_rejected(anon):
    """Endpoint protegido deve negar acesso sem token (401)."""
    r = anon.get(PROTECTED)
    assert r.status_code == 401, f"Esperado 401 sem token, obtido {r.status_code}"


def test_malformed_token_is_rejected(anon):
    anon.s.headers["Authorization"] = "Bearer not-a-real-jwt"
    r = anon.get(PROTECTED)
    assert r.status_code in (401, 403), f"Token malformado aceito: {r.status_code}"


def test_expired_token_is_rejected(user_a):
    """Forja um JWT expirado com claims do usuario e espera 401."""
    payload = {"sub": str(user_a.user_id), "exp": int(time.time()) - 3600}
    forged = jwt.encode(payload, "x", algorithm="HS256")
    user_a.s.headers["Authorization"] = f"Bearer {forged}"
    r = user_a.get(PROTECTED)
    assert r.status_code == 401, f"Token expirado aceito: {r.status_code}"


def test_login_rate_limiting(anon):
    """10 logins invalidos seguidos devem disparar 429 (anti brute force)."""
    codes = []
    for _ in range(10):
        r = anon.post("/auth/login",
                      json={"email": "usera@test.local", "password": "wrong"})
        codes.append(r.status_code)
    assert 429 in codes, f"Sem rate limiting no login. Codigos: {codes}"


def test_user_enumeration_uniform_error(anon):
    """Mensagem/codigo deve ser identica para usuario inexistente vs senha errada."""
    r_unknown = anon.post("/auth/login",
                          json={"email": "naoexiste@test.local", "password": "x"})
    r_wrongpw = anon.post("/auth/login",
                          json={"email": "usera@test.local", "password": "x"})
    assert r_unknown.status_code == r_wrongpw.status_code, "Codigos diferentes permitem enumeracao"
    assert r_unknown.text == r_wrongpw.text, "Mensagens diferentes permitem enumeracao"
