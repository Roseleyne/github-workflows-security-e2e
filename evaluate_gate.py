#!/usr/bin/env python3
"""
Security Gate: consolida os artefatos de todos os scanners e aplica a politica
de severidade. Retorna exit code != 0 (reprovando o build) se houver findings
acima do limite, ou se a suite de AuthZ/AuthN tiver falhas.

Entradas suportadas:
  - SARIF (Semgrep, Trivy)               -> security[security-severity] / level
  - JUnit XML (pytest AuthZ/AuthN)       -> <testsuite failures/errors>
  - ZAP report_json.json (DAST)          -> site[].alerts[].riskcode
  - MobSF mobsf-report.json (mobile)     -> appsec.high

Escreve um resumo em Markdown no GITHUB_STEP_SUMMARY.
"""
import argparse
import glob
import json
import os
import sys
import xml.etree.ElementTree as ET

SARIF_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
ZAP_RISK = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}


def rank(sev):
    return SARIF_SEV.get(sev.lower(), 0)


def parse_sarif(path, fail_ranks):
    """Conta findings SARIF cujo nivel >= limite."""
    hits = []
    try:
        data = json.load(open(path))
    except Exception:
        return hits
    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "sarif")
        # mapa ruleId -> security-severity
        rule_sev = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            props = rule.get("properties", {})
            ss = props.get("security-severity")
            if ss:
                try:
                    v = float(ss)
                    sev = "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low"
                    rule_sev[rule.get("id")] = sev
                except ValueError:
                    pass
        for res in run.get("results", []):
            level = res.get("level", "warning")
            sev = rule_sev.get(res.get("ruleId"))
            if not sev:
                sev = {"error": "high", "warning": "medium", "note": "low"}.get(level, "low")
            if rank(sev) >= fail_ranks:
                hits.append((tool, sev, res.get("ruleId", "")))
    return hits


def parse_junit(path):
    """Devolve (total, failures, errors)."""
    try:
        tree = ET.parse(path)
    except Exception:
        return (0, 0, 0)
    root = tree.getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    t = f = e = 0
    for s in suites:
        t += int(s.get("tests", 0))
        f += int(s.get("failures", 0))
        e += int(s.get("errors", 0))
    return (t, f, e)


def parse_zap(path, fail_ranks):
    hits = []
    try:
        data = json.load(open(path))
    except Exception:
        return hits
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = int(alert.get("riskcode", 0))
            sev = ZAP_RISK.get(risk, "INFO")
            if rank(sev) >= fail_ranks:
                hits.append(("ZAP", sev, alert.get("name", "")))
    return hits


def parse_mobsf(path):
    hits = []
    try:
        data = json.load(open(path))
    except Exception:
        return hits
    for item in data.get("appsec", {}).get("high", []):
        hits.append(("MobSF", "high", str(item)[:60]))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", required=True)
    ap.add_argument("--fail-on", default="HIGH,CRITICAL")
    ap.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY", "/dev/stdout"))
    args = ap.parse_args()

    fail_ranks = min(rank(s.strip()) for s in args.fail_on.split(",") if s.strip())

    sarif_hits, zap_hits, mobsf_hits = [], [], []
    authz_total = authz_fail = authz_err = 0

    for p in glob.glob(f"{args.artifacts}/**/*.sarif", recursive=True):
        sarif_hits += parse_sarif(p, fail_ranks)
    for p in glob.glob(f"{args.artifacts}/**/report_json.json", recursive=True):
        zap_hits += parse_zap(p, fail_ranks)
    for p in glob.glob(f"{args.artifacts}/**/mobsf-report.json", recursive=True):
        mobsf_hits += parse_mobsf(p)
    for p in glob.glob(f"{args.artifacts}/**/*results.xml", recursive=True):
        t, f, e = parse_junit(p)
        authz_total += t; authz_fail += f; authz_err += e

    total_blocking = len(sarif_hits) + len(zap_hits) + len(mobsf_hits) + authz_fail + authz_err

    lines = ["# Security Gate - Resultado", ""]
    lines.append(f"Politica: falhar em **{args.fail_on}**")
    lines.append("")
    lines.append("| Categoria | Bloqueantes |")
    lines.append("|---|---|")
    lines.append(f"| SAST/SCA/IaC (SARIF) | {len(sarif_hits)} |")
    lines.append(f"| DAST (ZAP) | {len(zap_hits)} |")
    lines.append(f"| Mobile (MobSF) | {len(mobsf_hits)} |")
    lines.append(f"| AuthZ/AuthN (testes {authz_total}) | {authz_fail + authz_err} |")
    lines.append("")
    if total_blocking:
        lines.append(f"## REPROVADO - {total_blocking} item(ns) bloqueante(s)")
        for tool, sev, name in (sarif_hits + zap_hits + mobsf_hits)[:50]:
            lines.append(f"- [{sev.upper()}] {tool}: {name}")
    else:
        lines.append("## APROVADO - nenhum item bloqueante")

    with open(args.summary, "a") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))

    sys.exit(1 if total_blocking else 0)


if __name__ == "__main__":
    main()
