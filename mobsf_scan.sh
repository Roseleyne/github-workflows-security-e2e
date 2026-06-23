#!/usr/bin/env bash
# Upload + scan estatico de APK via API REST do MobSF.
# Uso: mobsf_scan.sh <caminho.apk>
set -euo pipefail
APK="${1:?informe o caminho do APK}"
HOST="${MOBSF_HOST:-http://localhost:8000}"
KEY="${MOBSF_API_KEY:?defina MOBSF_API_KEY}"
OUT="security/mobile/mobsf-report.json"

echo ">> Upload $APK"
HASH=$(curl -s -F "file=@${APK}" "${HOST}/api/v1/upload" -H "Authorization: ${KEY}" | python3 -c "import sys,json;print(json.load(sys.stdin)['hash'])")

echo ">> Scan hash=$HASH"
curl -s -X POST "${HOST}/api/v1/scan" -H "Authorization: ${KEY}" --data "hash=${HASH}" > /dev/null

echo ">> Relatorio JSON -> $OUT"
curl -s -X POST "${HOST}/api/v1/report_json" -H "Authorization: ${KEY}" --data "hash=${HASH}" > "$OUT"

# Falha se houver findings high/critical no score de seguranca
python3 - "$OUT" << 'PY'
import json,sys
r=json.load(open(sys.argv[1]))
score=r.get("appsec",{}).get("security_score", r.get("security_score"))
high=len(r.get("appsec",{}).get("high",[]))
print(f"MobSF security_score={score} high_findings={high}")
sys.exit(1 if high and high>0 else 0)
PY
