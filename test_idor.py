"""
A2 - IDOR / Broken Object Level Authorization (BOLA - API1:2023).

Estrategia: user_a tenta ler/alterar/excluir recursos que pertencem a user_b
usando o identificador direto do objeto. Qualquer 2xx e falha de seguranca.
"""
import pytest


def _create_resource(client, payload):
    r = client.post("/api/v1/notes", json=payload)
    assert r.status_code in (200, 201), f"Setup falhou: {r.status_code} {r.text}"
    return r.json()["id"]


@pytest.fixture
def victim_note(user_b):
    """Recurso pertencente a user_b (vitima)."""
    return _create_resource(user_b, {"title": "privado-b", "body": "segredo de B"})


def test_idor_read_other_users_object(user_a, victim_note):
    """user_a NAO deve conseguir LER recurso de user_b."""
    r = user_a.get(f"/api/v1/notes/{victim_note}")
    assert r.status_code in (403, 404), \
        f"IDOR de leitura: user_a leu nota de user_b (HTTP {r.status_code})"


def test_idor_update_other_users_object(user_a, victim_note):
    """user_a NAO deve conseguir ALTERAR recurso de user_b."""
    r = user_a.put(f"/api/v1/notes/{victim_note}", json={"title": "hacked"})
    assert r.status_code in (403, 404), \
        f"IDOR de escrita: user_a alterou nota de user_b (HTTP {r.status_code})"


def test_idor_delete_other_users_object(user_a, victim_note):
    """user_a NAO deve conseguir EXCLUIR recurso de user_b."""
    r = user_a.delete(f"/api/v1/notes/{victim_note}")
    assert r.status_code in (403, 404), \
        f"IDOR de exclusao: user_a excluiu nota de user_b (HTTP {r.status_code})"


@pytest.mark.parametrize("probe_id", [1, 2, 1000, 999999, "00000000-0000-0000-0000-000000000001"])
def test_idor_sequential_id_probe(user_a, probe_id):
    """Varredura de IDs sequenciais nao deve vazar objetos de terceiros."""
    r = user_a.get(f"/api/v1/notes/{probe_id}")
    if r.status_code == 200:
        owner = r.json().get("owner_id")
        assert str(owner) == str(user_a.user_id), \
            f"IDOR: id={probe_id} retornou objeto de owner={owner}"
