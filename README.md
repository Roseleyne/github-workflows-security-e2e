# Teste de Seguranca E2E Automatizado (Web + API + Mobile)

Cenario de seguranca executado de ponta a ponta na pipeline (GitHub Actions),
com foco principal em **AuthN/AuthZ** e camadas de apoio DevSecOps (SAST, SCA,
secrets, IaC/container, DAST e mobile).

## Estrutura
```
.github/workflows/security-e2e.yml   Pipeline orquestradora (9 jobs)
docker-compose.test.yml              Stack efemera web+api+db com seeds
security/
  authz/                             Suite pytest AuthN/AuthZ (foco)
    conftest.py                      Fixtures + clientes autenticados
    test_authentication.py          A1 - AuthN
    test_idor.py                     A2 - IDOR / BOLA
    test_privilege_escalation.py     A3 - escalonamento vert/horizontal
    test_jwt_attacks.py             A4 - alg=none, claim tampering, weak secret
    test_session_management.py       A5 - logout/refresh, cookies
    requirements.txt
  semgrep-rules.yml                  Regras SAST custom
  gitleaks.toml                      Politica de segredos
  zap/rules.tsv                      Politica DAST (ZAP)
  mobile/mobsf_scan.sh               Scan estatico de APK (MobSF)
  gate/evaluate_gate.py              Security Gate (consolida + aprova/reprova)
docs/Plano_Teste_Seguranca_E2E.docx  Plano formal para proposta
```

## Pre-requisitos
1. Imagens/Dockerfile da app (api em :3000, web em :8080, /health e /openapi.json).
2. Seeds de contas de teste (`SEED_TEST_USERS=true`): usera, userb, admin.
3. Secrets no repositorio:
   `TEST_USER_A`, `TEST_USER_B`, `TEST_ADMIN` (formato `email:senha`),
   `JWT_SECRET`, `JWT_SECRET_GUESS`, `ZAP_AUTH_TOKEN`, `MOBSF_API_KEY`.

## Execucao local (apenas AuthZ/AuthN)
```bash
docker compose -f docker-compose.test.yml up -d --build
pip install -r security/authz/requirements.txt
pytest security/authz -v
```

## Politica de gate
Reprova o build (exit!=0) se houver finding HIGH/CRITICAL em qualquer scanner
ou qualquer teste de AuthZ/AuthN falho. Ajuste em `FAIL_ON_SEVERITY`.

> Uso restrito a ambientes proprios/autorizados. Testes de seguranca exigem
> autorizacao formal do dono do sistema.
