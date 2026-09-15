#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────────────
# REVENANT — VPS Provisioning Script
# Target: Ubuntu 22.04 LTS (fresh install)
# What: Docker, Docker Compose, Go, Python, Node, Postgres 16+pgvector,
#        Redis, git, and the REVENANT directory scaffold.
#
# Usage:
#   curl -sL <raw-url>/provision-vps.sh | bash
#   # ...or upload and run:
#   chmod +x provision-vps.sh && ./provision-vps.sh
# ───────────────────────────────────────────────────────────────────────
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
REVENANT_HOME="${REVENANT_HOME:-/opt/revenant}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── Pre-flight checks ────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  error "Run as root (use sudo)."
fi

if ! grep -qi ubuntu /etc/os-release 2>/dev/null; then
  warn "Not Ubuntu — proceeding anyway, but this script is tested on Ubuntu 22.04."
fi

info "REVENANT VPS provisioning starting..."
info "Target directory: $REVENANT_HOME"

# ── 1. System packages ────────────────────────────────────────────────
info "Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
  curl wget git jq unzip software-properties-common \
  apt-transport-https ca-certificates gnupg lsb-release \
  build-essential pkg-config \
  ufw fail2ban unattended-upgrades \
  htop tmux tmux-plugin-manager

info "System packages installed."

# ── 2. Firewall ───────────────────────────────────────────────────────
info "Configuring firewall (UFW)..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 3000/tcp   # Next.js dashboard
ufw allow 8080/tcp   # GoFiber API
ufw allow 5432/tcp   # Postgres (local only — close before production)
ufw allow 6379/tcp   # Redis  (local only)
ufw --force enable
info "Firewall active."

# ── 3. Docker ─────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  info "Installing Docker..."
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker
  info "Docker installed."
else
  info "Docker already installed: $(docker --version)"
fi

# ── 4. Docker Compose (standalone, for legacy compose files) ──────────
if ! docker compose version &>/dev/null; then
  info "Installing Docker Compose plugin..."
  apt-get install -y -qq docker-compose-plugin
fi
info "Docker Compose: $(docker compose version 2>&1 | head -1)"

# ── 5. Go ─────────────────────────────────────────────────────────────
GO_VERSION="1.24.4"
if ! command -v go &>/dev/null || ! go version 2>/dev/null | grep -q "$GO_VERSION"; then
  info "Installing Go $GO_VERSION..."
  curl -sSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | \
    tar -C /usr/local -xzf -
  cat > /etc/profile.d/go.sh <<'GOENV'
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
export GOPATH=$HOME/go
export GOROOT=/usr/local/go
GOENV
  source /etc/profile.d/go.sh
  info "Go installed: $(go version)"
else
  info "Go already installed: $(go version)"
fi

# ── 6. Python 3 + pip + venv ──────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  info "Installing Python 3..."
  apt-get install -y -qq python3 python3-pip python3-venv
fi
info "Python: $(python3 --version)"

# ── 7. Node.js 20 LTS ────────────────────────────────────────────────
if ! command -v node &>/dev/null || ! node --version 2>/dev/null | grep -q 'v20'; then
  info "Installing Node.js 20 LTS..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y -qq nodejs
  info "Node.js: $(node --version)"
else
  info "Node.js already installed: $(node --version)"
fi

# ── 8. PostgreSQL 16 ──────────────────────────────────────────────────
if ! command -v psql &>/dev/null || ! psql --version 2>/dev/null | grep -q '16'; then
  info "Installing PostgreSQL 16..."
  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | \
    gpg --dearmor -o /etc/apt/keyrings/pgdg.gpg
  echo \
    "deb [signed-by=/etc/apt/keyrings/pgdg.gpg] \
    http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list
  apt-get update -qq
  apt-get install -y -qq postgresql-16 postgresql-16-pgvector
  systemctl enable --now postgresql
  info "PostgreSQL 16 installed."
else
  info "PostgreSQL already installed."
fi

# Create REVENANT database + role (idempotent — safe to rerun)
info "Setting up REVENANT database..."
su - postgres -c "psql -c \"SELECT 1 FROM pg_roles WHERE rolname='revenant'\"" | grep -q 1 \
  || su - postgres -c "psql -c \"CREATE ROLE revenant WITH LOGIN PASSWORD 'revenant_dev'\""
su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname='revenant'\"" | grep -q 1 \
  || su - postgres -c "createdb -O revenant revenant"
su - postgres -d revenant -c "CREATE EXTENSION IF NOT EXISTS vector;"
info "Database 'revenant' ready with pgvector."

# ── 9. Redis ──────────────────────────────────────────────────────────
if ! command -v redis-server &>/dev/null; then
  info "Installing Redis..."
  apt-get install -y -qq redis-server
  systemctl enable --now redis-server
  info "Redis installed."
else
  info "Redis already installed."
fi

# ── 10. REVENANT directory scaffold ───────────────────────────────────
info "Creating REVENANT directory scaffold at $REVENANT_HOME..."
mkdir -p "$REVENANT_HOME"/{repos,platform,control-plane,orchestrator,adapters,engines,reporting,deployments,playbooks,configs,docker,scripts,docs,evidence}
info "Directory scaffold created."

# ── 11. Summary ───────────────────────────────────────────────────────
echo ""
info "══════════════════════════════════════════════════════"
info " REVENANT VPS PROVISIONING COMPLETE"
info "══════════════════════════════════════════════════════"
echo ""
echo "  Location:     $REVENANT_HOME"
echo "  Docker:       $(docker --version)"
echo "  Docker Comp:  $(docker compose version 2>&1 | head -1)"
echo "  Go:           $(go version 2>&1)"
echo "  Python:       $(python3 --version)"
echo "  Node.js:      $(node --version)"
echo "  PostgreSQL:   $(psql --version | head -1)"
echo "  Redis:        $(redis-server --version)"
echo ""
echo "  Database:     revenant (user: revenant / pass: revenant_dev)"
echo "  ⚠ CHANGE THE DATABASE PASSWORD before production use."
echo ""
echo "  Next steps:"
echo "    1. Clone Pentest Swarm AI into $REVENANT_HOME/repos/pentest-swarm-ai/"
echo "    2. Run the build-and-verify script"
echo "    3. Deploy docker-compose stack"
echo ""
