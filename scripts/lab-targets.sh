#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────────────
# REVENANT — Lab Targets
# Brings up OWASP sanctioned lab apps on their own Docker network
# (`revenant-lab`), isolated from the platform network (`revenant`).
# These are the ONLY sanctioned targets for Phase 1 verification.
# ───────────────────────────────────────────────────────────────────────
set -euo pipefail

NET="revenant-lab"
docker network create "$NET" 2>/dev/null || true

start() {
  local name="$1"; shift
  local port="$1"; shift
  docker run -d --name "$name" --network "$NET" \
    -p "127.0.0.1:$port:${PORT:-80}" --restart unless-stopped "$@"
  echo "[✓] $name → http://127.0.0.1:$port  (sanctioned lab target)"
}

case "${1:-status}" in
  status)
    docker ps --filter network="$NET" --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'
    ;;
  start)
    start crapi       30013 ghcr.io/owasp/crapi:latest
    start juiceshop   3000   bkimminich/juice-shop:latest
    start vampi       3001   erev0s/vampi:latest
    start dvga        3002   ojaswa1942/dvga:latest
    ;;
  stop)
    for c in crapi juiceshop vampi dvga; do docker rm -f "$c" 2>/dev/null || true; done
    echo "[✓] Lab targets stopped."
    ;;
  *)
    echo "Usage: $0 {start|stop|status}"
    exit 1
    ;;
esac