import json
import urllib.request
import os
import subprocess

url = "https://api.github.com/repos/BishopFox/cloudfox/releases/latest"
req = urllib.request.Request(url, headers={"User-Agent": "REVENANT-Setup"})
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())

print("Latest CloudFox release:", data.get("tag_name"))
download_url = None
asset_name = None
for asset in data.get("assets", []):
    name = asset["name"].lower()
    if "linux" in name and ("amd64" in name or "x86_64" in name):
        download_url = asset["browser_download_url"]
        asset_name = asset["name"]
        break

if not download_url:
    print("Could not find linux amd64 asset. All assets:")
    for asset in data.get("assets", []):
        print(" -", asset["name"])
    exit(1)

print(f"Downloading {asset_name} from {download_url}...")
dest_path = f"/tmp/{asset_name}"
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "curl", "-sL", download_url, "-o", dest_path], check=True)

print("Extracting cloudfox in WSL...")
if asset_name.endswith(".zip"):
    subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "unzip", "-q", "-o", dest_path, "-d", "/tmp/cloudfox_extracted"], check=True)
elif asset_name.endswith(".tar.gz") or asset_name.endswith(".tgz"):
    subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "mkdir", "-p", "/tmp/cloudfox_extracted"], check=True)
    subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "tar", "-xzf", dest_path, "-C", "/tmp/cloudfox_extracted"], check=True)
else:
    subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "cp", dest_path, "/usr/local/bin/cloudfox"], check=True)
    subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "chmod", "+x", "/usr/local/bin/cloudfox"], check=True)

subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "bash", "-c", "find /tmp/cloudfox_extracted -name cloudfox -type f -exec cp {} /usr/local/bin/cloudfox \\; -exec chmod +x /usr/local/bin/cloudfox \\;"], check=False)
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "cloudfox", "--version"])
print("CloudFox setup complete.")
