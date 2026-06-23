"""
Fixtures compartilhadas para a suite AuthZ/AuthN.

Modelo de contas (seeds do ambiente efemero, nunca producao):
  - user_a  : usuario comum, dono do recurso "A"
  - user_b  : usuario comum, dono do recurso "B" (vitima nos testes IDOR)
  - admin   : papel privilegiado

Cada fixture autentica e devolve um cliente HTTP com o token no header.
As credenciais vem de variaveis de ambiente (GitHub Secrets), formato:
  USER_A_CREDS="email:senha"
"""
import os
import json
import requests
import pytest

API = os.environ.get("API_BASE_URL", "http://localhost:3000")
APP = os.environ.get("APP_BASE_URL", "http://localhost:8080")
TIMEOUT = 15


def _split_creds(env_name, default):
    raw = os.environ.get(env_name, default)
    email, _, password = raw.partition(":")
    return {"email": email, "password": password}


class AuthClient:
    """Cliente HTTP fino que carrega o token e expoe helpers."""

    def __init__(self, base_url, token=None, user_id=None, role=None):
        self.base = base_url.rstrip("/")
        self.token = token
        self.user_id = user_id
        self.role = role
        self.s = requests.Session()
        if token:
            self.s.headers["Authorization"] = f"Bearer {token}"

    def request(self, method, path, **kw):
        kw.setdefault("timeout", TIMEOUT)
        return self.s.request(method, f"{self.base}{path}", **kw)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)

    def put(self, path, **kw):
        return self.request("PUT", path, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)


def _login(creds):
    """Autentica via /auth/login e devolve (token, user_id, role)."""
    r = requests.post(f"{API}/auth/login", json=creds, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    token = data.get("access_token") or data.get("token")
    user = data.get("user", {})
    return token, user.get("id"), user.get("role")


@pytest.fixture(scope="session")
def anon():
    """Cliente sem autenticacao."""
    return AuthClient(API)


@pytest.fixture(scope="session")
def user_a():
    creds = _split_creds("USER_A_CREDS", "usera@test.local:Passw0rd!A")
    token, uid, role = _login(creds)
    return AuthClient(API, token, uid, role)


@pytest.fixture(scope="session")
def user_b():
    creds = _split_creds("USER_B_CREDS", "userb@test.local:Passw0rd!B")
    token, uid, role = _login(creds)
    return AuthClient(API, token, uid, role)


@pytest.fixture(scope="session")
def admin():
    creds = _split_creds("ADMIN_CREDS", "admin@test.local:Passw0rd!Adm")
    token, uid, role = _login(creds)
    return AuthClient(API, token, uid, role)
