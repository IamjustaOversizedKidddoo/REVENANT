#!/usr/bin/env bash
# REVENANT — SMB Lab Setup for NetExec Live Testing
# Sets up a minimal Samba server with an anonymous-accessible share inside WSL2.
# Run as root (or with sudo) inside WSL2.

set -euo pipefail

SHARE_DIR="/srv/smb/revenant_testshare"
SMB_CONF="/tmp/revenant_smb.conf"
SHARE_NAME="revenant-share"
SMB_PORT=445

echo "[+] Installing Samba..."
apt-get update -qq && apt-get install -y -qq samba > /dev/null 2>&1

echo "[+] Creating share directory: $SHARE_DIR"
mkdir -p "$SHARE_DIR"
chmod 777 "$SHARE_DIR"
echo "REVENANT SMB Lab Test File" > "$SHARE_DIR/README.txt"

echo "[+] Writing smb.conf to $SMB_CONF"
cat > "$SMB_CONF" <<'EOF'
[global]
   workgroup = REVENANT
   server string = REVENANT-SMB-LAB
   netbios name = SMBLAB
   security = user
   map to guest = bad user
   guest account = nobody
   smb ports = 445
   log level = 1
   server role = standalone server
   passdb backend = smbpasswd
   # Disable signing to simulate misconfigured host for testing
   server signing = disabled
   client signing = disabled

[revenant-share]
   path = /srv/smb/revenant_testshare
   browseable = yes
   read only = yes
   guest ok = yes
   guest only = yes
   comment = REVENANT NetExec Live Test Share
EOF

echo "[+] Stopping any existing smbd..."
pkill smbd 2>/dev/null || true
sleep 1

echo "[+] Starting smbd with test config..."
smbd --foreground --no-process-group --configfile="$SMB_CONF" &
SMBD_PID=$!
echo "[+] smbd started (PID=$SMBD_PID)"
sleep 2

# Verify smbd is listening
if ss -tlnp 2>/dev/null | grep -q ":445"; then
    echo "[CONFIRMED] smbd listening on port 445"
else
    echo "[WARN] smbd may not be on port 445 — check 'ss -tlnp' manually"
fi

# Print WSL2 IP for use by tests
WSL_IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
WSL_IP=${WSL_IP:-127.0.0.1}
echo "WSL_IP=$WSL_IP"
echo "SMBD_PID=$SMBD_PID"
echo "SHARE_NAME=$SHARE_NAME"
echo "[+] SMB lab ready — run: nxc smb $WSL_IP -u '' -p '' --shares --no-progress"
