#!/usr/bin/env bash
set -e

mkdir -p /tmp/install_tools
cd /tmp/install_tools

echo "=== Installing Katana Linux ==="
curl -sL https://github.com/projectdiscovery/katana/releases/download/v1.7.0/katana_1.7.0_linux_amd64.zip -o katana.zip
unzip -o katana.zip katana
mv katana /usr/local/bin/katana
chmod +x /usr/local/bin/katana

echo "=== Installing HTTPX Linux ==="
curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip -o httpx.zip
unzip -o httpx.zip httpx
mv httpx /usr/local/bin/httpx
chmod +x /usr/local/bin/httpx

echo "=== Installing Subfinder Linux ==="
curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip -o subfinder.zip
unzip -o subfinder.zip subfinder
mv subfinder /usr/local/bin/subfinder
chmod +x /usr/local/bin/subfinder

echo "=== Installing Nuclei Linux ==="
curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -o nuclei.zip
unzip -o nuclei.zip nuclei
mv nuclei /usr/local/bin/nuclei
chmod +x /usr/local/bin/nuclei

echo "=== Installing FFUF Linux ==="
curl -sL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -o ffuf.tar.gz
tar -xzf ffuf.tar.gz ffuf
mv ffuf /usr/local/bin/ffuf
chmod +x /usr/local/bin/ffuf

echo "=== Installing Gitleaks Linux ==="
curl -sL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz -o gitleaks.tar.gz
tar -xzf gitleaks.tar.gz gitleaks
mv gitleaks /usr/local/bin/gitleaks
chmod +x /usr/local/bin/gitleaks

echo "=== Installing TruffleHog Linux ==="
curl -sL https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.5/trufflehog_3.97.5_linux_amd64.tar.gz -o trufflehog.tar.gz
tar -xzf trufflehog.tar.gz trufflehog
mv trufflehog /usr/local/bin/trufflehog
chmod +x /usr/local/bin/trufflehog

rm -rf /tmp/install_tools
echo "ALL LINUX TOOLS INSTALLED TO /usr/local/bin!"
