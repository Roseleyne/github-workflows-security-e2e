"""
A4 - Ataques a JWT (token forgery).
Cobre: alg=none, confusao de algoritmo (RS256->HS256), assinatura fraca
(brute force de secret), e adulteracao de claims (sub/role) sem reassinar.
"""
import os
import json
import base64
import jwt
import pytest

PROTECTED = "/api/v1/users/me"
ADMIN = "/api/v1/admin/users"


def _b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def test_alg_none_is_rejected(user_a):
    """JWT com alg=none e sem assinatura deve ser recusado."""
    header = _b64({"alg": "none", "typ": "JWT"})
    payload = _b64({"sub": str(user_a.user_id), "role": "admin"})
    token = f"{header}.{payload}."
    user_a.s.headers["Authorization"] = f"Bearer {token}"
    r = user_a.get(ADMIN)
    assert r.status_code in (401, 403), f"alg=none aceito (HTTP {r.status_code})"


def test_claim_tampering_without_resign(user_a):
    """Alterar 'role' no payload sem reassinar deve invalidar a assinatura."""
    parts = user_a.token.split(".")
    tampered_payload = _b64({"sub": str(user_a.user_id), "role": "admin"})
    forged = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    user_a.s.headers["Authorization"] = f"Bearer {forged}"
    r = user_a.get(ADMIN)
    assert r.status_code in (401, 403), \
        f"Claim adulterada aceita sem reassinatura (HTTP {r.status_code})"


def test_weak_secret_not_guessable(user_a):
    """
    Se um secret fraco for fornecido (JWT_SECRET_GUESS), forjamos um token
    admin assinado com ele. Aceitacao = secret fraco/conhecido em uso.
    """
    guess = os.environ.get("JWT_SECRET_GUESS", "secret")
    forged = jwt.encode({"sub": str(user_a.user_id), "role": "admin"},
                        guess, algorithm="HS256")
    user_a.s.headers["Authorization"] = f"Bearer {forged}"
    r = user_a.get(ADMIN)
    assert r.status_code in (401, 403), \
        "Secret fraco/conhecido aceito: token admin forjado funcionou"


def test_algorithm_confusion_rs_to_hs(user_a):
    """
    Confusao RS256->HS256: assina HS256 usando a chave PUBLICA como secret.
    Requer arquivo da chave publica em security/authz/public_key.pem (opcional).
    """
    pub_path = os.path.join(os.path.dirname(__file__), "public_key.pem")
    if not os.path.exists(pub_path):
        pytest.skip("public_key.pem nao fornecida; teste de confusao de alg pulado")
    with open(pub_path) as f:
        pub = f.read()
    forged = jwt.encode({"sub": str(user_a.user_id), "role": "admin"},
                        pub, algorithm="HS256")
    user_a.s.headers["Authorization"] = f"Bearer {forged}"
    r = user_a.get(ADMIN)
    assert r.status_code in (401, 403), \
        "Confusao de algoritmo RS256->HS256 aceita"
