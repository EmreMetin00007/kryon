#!/bin/bash
# CCO RAG Bootstrap — wrapper script
# Kullanım: bash scripts/rag-bootstrap.sh [--dry-run] [--seed-only] [--cve-count N]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BOOTSTRAP_PY="$SCRIPT_DIR/rag-bootstrap.py"

# Renk kodları
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}CCO RAG Bootstrap${NC}"
echo "Proje: $PROJECT_DIR"

# Python kontrolü
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}HATA: python3 bulunamadı${NC}"
    exit 1
fi

# Runtime dependencies are installed by the project installer/lockfile. This
# wrapper never mutates the Python environment or executes project .env files.
if ! python3 -c "import chromadb, requests" 2>/dev/null; then
    echo -e "${RED}HATA: RAG bağımlılıkları eksik — project runtime dependencies kurulmalı${NC}"
    exit 1
fi

# Bootstrap çalıştır
export CCO_HOME="${CCO_HOME:-$PROJECT_DIR/.cco}"
exec python3 "$BOOTSTRAP_PY" "$@"
