#!/usr/bin/env bash
# blind_run.sh — kör turu OS seviyesinde kilitler (bwrap):
#   kök dosya sistemi salt-okunur; yalnızca CCO_WORKDIR (vars. ~/cco-work)
#   ve /tmp yazılabilir. Ölçüm aletine (repo + validator) ajan yazamaz.
# Kullanım: CCO_BLIND_MODE=1 ./scripts/blind_run.sh python3 scripts/agent_cli.py plan ...
set -euo pipefail

if ! command -v bwrap >/dev/null 2>&1; then
  echo "HATA: bwrap yok — OS izolasyonu kurulamaz, kör tur başlatılmaz." >&2
  exit 2
fi

WORKDIR="${CCO_WORKDIR:-$HOME/cco-work}"
mkdir -p "$WORKDIR"

export CCO_BLIND_MODE=1
export CCO_WORKDIR="$WORKDIR"
# Göreli yazan aletler (örn. .cco/approvals) çalışma dizinine düşsün:
cd "$WORKDIR"

exec bwrap \
  --ro-bind / / \
  --bind "$WORKDIR" "$WORKDIR" \
  --bind /tmp /tmp \
  --dev-bind /dev /dev \
  --proc /proc \
  --die-with-parent \
  -- "$@"
