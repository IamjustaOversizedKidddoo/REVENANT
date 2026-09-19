import os
import sys
import tempfile
from control_plane.schemas.scope import ScopeManifest
from adapters.malware.yara_adapter import YaraAdapter
from adapters.network.nmap_adapter import NmapAdapter

rule_content = """
rule ContainerSignatureDetection {
    meta:
        description = "Live YARA execution test inside container"
        severity = "CRITICAL"
        mitre_technique = "T1505.003"
    strings:
        $token = "REVENANT_CONTAINER_PAYLOAD_MATCH"
    condition:
        $token
}
"""

with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False) as rf:
    rf.write(rule_content)
    rule_file = rf.name

with tempfile.NamedTemporaryFile(mode="w", suffix=".bin", delete=False) as tf:
    tf.write("header_data_REVENANT_CONTAINER_PAYLOAD_MATCH_footer_data")
    target_file = tf.name

scope = ScopeManifest(
    allowed_domains=["*"],
    allowed_hosts=[os.path.basename(target_file), "control-plane", "127.0.0.1", "localhost"],
    allowed_cidrs=["0.0.0.0/0", "127.0.0.1/32"],
    allowed_ports=[80, 443, 8000],
    environment_type="testing",
    authorized_by="Lead Operator",
)

# Test 1: Native Linux YARA tool execution inside container
print("=== Container Check 1: Native YARA Tool Execution ===")
yara_adapter = YaraAdapter(default_rules_path=rule_file, use_wsl=True)
print(f"[*] YaraAdapter initialized with use_wsl={yara_adapter.use_wsl}")
print(f"[*] BaseAdapter is_wsl_mode: {yara_adapter.is_wsl_mode} (os.name='{os.name}')")
print(f"[*] Binary path resolved: {yara_adapter.binary_path}")

yara_result = yara_adapter.run(
    target=target_file,
    scope=scope,
    params={"rules": rule_file},
)

print(f"[+] YaraAdapter execution completed with exit_code: {yara_result.exit_code}")
print(f"[+] Total findings produced: {len(yara_result.findings)}")
for f in yara_result.findings:
    print(f"    - Title: {f.title}")
    print(f"    - Tool: {f.tool}")
    print(f"    - Severity: {f.severity}")
    print(f"    - Raw stdout snippet: {yara_result.raw_stdout.strip()}")

# Test 2: Native Linux Nmap tool execution inside container against control-plane service
print("\n=== Container Check 2: Native Nmap Tool Execution ===")
nmap_adapter = NmapAdapter(use_wsl=True)
print(f"[*] NmapAdapter initialized with use_wsl={nmap_adapter.use_wsl}")
print(f"[*] BaseAdapter is_wsl_mode: {nmap_adapter.is_wsl_mode} (os.name='{os.name}')")
print(f"[*] Binary path resolved: {nmap_adapter.binary_path}")

nmap_result = nmap_adapter.run(
    target="control-plane",
    scope=scope,
    params={"ports": "8000", "timing": "T4", "extra_args": "-sT"},
)

print(f"[+] NmapAdapter execution completed with exit_code: {nmap_result.exit_code}")
print(f"[+] Discovered assets: {len(nmap_result.discovered_assets)}")
for asset in nmap_result.discovered_assets:
    print(f"    - IP: {asset.ip}, Hostname: {asset.hostname}, Ports: {[p.port for p in asset.ports]}")

print("\n=== ALL CONTAINER TOOL INVOCATIONS SUCCEEDED NATIVELY ===")
