#!/usr/bin/env bash
# blind_approve.sh — kör tur grantlerini AJANIN GÖRECEĞİ DB'ye yazar.
# blind_run.sh CCO_HOME'u izole ettiği için grantler de aynı CCO_HOME ile
# verilmelidir; yoksa ajan boş approvals tablosu görür (wsa-blind4 dersi).
# Kullanım: CCO_WORKDIR=~/cco-work/wsa-blind4 ./scripts/blind_approve.sh <host> [ttl]
set -euo pipefail
HOST="${1:?host gerekli}"; TTL="${2:-3600}"
WORKDIR="${CCO_WORKDIR:-$HOME/cco-work}"
export CCO_HOME="$WORKDIR/work"
mkdir -p "$CCO_HOME"
for pat in 'kali-tools_*' 'validator_*' 'browser_*' 'web-advanced_*' 'agent-browse_*' 'webfetch' 'bash'; do
  python3 "$(dirname "$0")/policy_gate_cli.py" approve \
    --tool-pattern "$pat" --target-pattern "$HOST" --ttl "$TTL" \
    --reason "blind blackbox measurement round (aligned CCO_HOME)" >/dev/null
done
echo "grants -> CCO_HOME=$CCO_HOME host=$HOST"
