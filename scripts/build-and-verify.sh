#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────────────
# REVENANT — Build & Verify Pentest Swarm AI baseline
#
# Clones Pentest Swarm AI, builds it, spins up the interactive lab
# target, and runs the sequential 5-phase pipeline against it.
#
# Requires: provision-vps.sh already run (Go, Docker, Postgres, Redis)
#
# Usage:
#   ./build-and-verify.sh            # full flow
#   ./build-and-verify.sh --build    # build only
#   ./build-and-verify.sh --verify   # run lab + assessment only
# ───────────────────────────────────────────────────────────────────────
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$(dirname "$SCRIPT_DIR")" && pwd)"
REVENANT_HOME="${REVENANT_HOME:-/opt/revenant}"
PENTEST_DIR="$REVENANT_HOME/repos/pentest-swarm-ai"
BRANCH="${PENTEST_BRANCH:-master}"

# LLM provider + key (required for the AI brain)
ANTHROPIC_KEY="${ANTHROPIC_API_KEY:-}"
OPENAI_KEY="${OPENAI_API_KEY:-}"

MODE="${1:-full}"
TARGET="${PENTEST_TARGET:-http://localhost:30013}"   # crAPI default port
TARGET_NAME="${PENTEST_TARGET_NAME:-crapi}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── Check key ─────────────────────────────────────────────────────────
require_key() {
  if [ -z "$ANTHROPIC_KEY" ] && [ -z "$OPENAI_KEY" ]; then
    error "No LLM API key set. Pass ANTHROPIC_API_KEY=... or OPENAI_API_KEY=... (AI brain needs one)."
  fi
}

# ── Build ─────────────────────────────────────────────────────────────
do_build() {
  if [ ! -d "$PENTEST_DIR/.git" ]; then
    info "Cloning Pentest Swarm AI (branch $BRANCH)..."
    git clone --depth 1 -b "$BRANCH" \
      https://github.com/Armur-Ai/Pentest-Swarm-AI.git "$PENTEST_DIR"
  else
    info "Pentest Swarm AI already cloned at $PENTEST_DIR — pulling latest."
    git -C "$PENTEST_DIR" pull --rebase || true
  fi

  info "Building Pentest Swarm AI..."
  cd "$PENTEST_DIR"
  env CGO_ENABLED=0 go build -o "$REVENANT_HOME/bin/pentestswarm" ./cmd/pentestswarm
  info "Built: $REVENANT_HOME/bin/pentestswarm"
  "$REVENANT_HOME/bin/pentestswarm" --help >/dev/null 2>&1 \
    && info "Binary runs." || warn "Binary built but --help failed."
}

# ── Lab target (crAPI) ────────────────────────────────────────────────
do_lab() {
  if docker ps --format '{{.Names}}' | grep -q "^crapi$"; then
    info "crAPI already running."
    return
  fi
  info "Starting crAPI lab target (OWASP flawed API)..."
  # crAPI is the OWASP community API challenge — safe, self-contained, local network only.
  docker run -d --name crapi --network revenant \
    -p 127.0.0.1:30013:80 \
    --restart unless-stopped \
    ghcr.io/owasp/crapi:latest 2>/dev/null \
  || {
    warn "crAPI image not found — spinning up a simpler sanctioned target (hello-world node) instead."
    docker run -d --name revenant-lab --network revenant \
      -p 127.0.0.1:30013:80 --restart unless-stopped \
      ghcr.io/hello-world-node:latest 2>/dev/null \
      || docker run -d --name revenant-lab -p 127.0.0.1:30013:80 --restart unless-stopped nginx:alpine
  }
  info "Lab target up at $TARGET"
}

# ── Verify / run assessment ───────────────────────────────────────────
do_verify() {
  require_key
  info "Running assessment against $TARGET_NAME ($TARGET)..."

  # Ensure the lab network exists for isolation
  docker network create revenant 2>/dev/null || true

  cd "$PENTEST_DIR"
  "$REVENANT_HOME/bin/pentestswarm" \
    run \
    --target "$TARGET_NAME" \
    --scopes "$TARGET" \
    --provider "${LLM_PROVIDER:-anthropic}" \
    --key "${ANTHROPIC_KEY:-$OPENAI_KEY}" \
    --output "$REVENANT_HOME/evidence/$TARGET_NAME" \
    --format json,md,html \
    --non-interactive \
    --max-hours "${MAX_HOURS:-3}" \
    "$@"
  info "Assessment complete. Reports at $REVENANT_HOME/evidence/$TARGET_NAME/"
  ls -la "$REVENANT_HOME/evidence/$TARGET_NAME" 2>/dev/null || true
}

# ── Dispatch ──────────────────────────────────────────────────────────
case "$MODE" in
  --build)  require_key; do_build ;;
  --verify) do_lab; do_verify ;;
  full|*)   require_key; do_build; do_lab; do_verify ;;
esac

info "══════════════════════════════════════════════════════"
info " BUILD + VERIFY FLOW COMPLETE"
info "══════════════════════════════════════════════════════"