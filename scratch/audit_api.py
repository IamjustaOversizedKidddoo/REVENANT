import json
import httpx
import jsonschema

API_BASE = "http://127.0.0.1:8000"

print("=== MILESTONE 4 AUDIT: LIVE FASTAPI CONTROL PLANE ===")

client = httpx.Client(base_url=API_BASE, timeout=60.0)

# Check Health
res = client.get("/api/v1/health")
print(f"1. Health Check: HTTP {res.status_code} -> {res.json()}")
assert res.status_code == 200

# (a) Out-of-Scope Target -> Expect HTTP 400
print("\n2. Testing Out-of-Scope Target Rejection (Layer 1 Scope Intake Gate)...")
payload_out_of_scope = {
    "target": "http://169.254.169.254/latest/meta-data/",
    "scope": {
        "name": "audit-scope",
        "allowed_hosts": ["127.0.0.1"]
    }
}
res_blocked = client.post("/api/v1/campaigns", json=payload_out_of_scope)
print(f"   Response Code: HTTP {res_blocked.status_code}")
print(f"   Response Body: {res_blocked.json()}")
assert res_blocked.status_code == 400
assert res_blocked.json()["detail"]["error"] == "SCOPE_VIOLATION"
print("   -> Confirmed: HTTP 400 and SCOPE_VIOLATION returned correctly!")

# (b) In-Scope Target -> Run Campaign and Return Findings
print("\n3. Testing In-Scope Campaign Creation against Lab Target (http://127.0.0.1:3000)...")
payload_in_scope = {
    "target": "http://127.0.0.1:3000",
    "scope": {
        "name": "lab-scope",
        "allowed_hosts": ["127.0.0.1"]
    },
    "max_iterations": 5
}
res_campaign = client.post("/api/v1/campaigns", json=payload_in_scope)
print(f"   Response Code: HTTP {res_campaign.status_code}")
camp_data = res_campaign.json()
campaign_id = camp_data["campaign_id"]
print(f"   Campaign ID: {campaign_id}")
print(f"   Status: {camp_data['status']}")
print(f"   Summary: {camp_data['summary']}")
assert res_campaign.status_code == 201

# Fetch Findings Endpoint
res_findings = client.get(f"/api/v1/campaigns/{campaign_id}/findings")
findings = res_findings.json()
print(f"   Fetched Findings count: {len(findings)}")
for f in findings:
    print(f"    - [{f['severity']}] {f['title']} ({f['tool']})")
assert len(findings) > 0

# Fetch Assets Endpoint
res_assets = client.get(f"/api/v1/campaigns/{campaign_id}/assets")
assets = res_assets.json()
print(f"   Fetched Assets count: {len(assets)}")
assert len(assets) > 0

# (c) All four report formats download & validate
print("\n4. Testing All 4 Report Formats...")

# 4.1 Markdown
res_md = client.get(f"/api/v1/campaigns/{campaign_id}/report?format=markdown")
assert res_md.status_code == 200
assert "REVENANT Security Assessment Report" in res_md.text
print(f"   - Markdown: HTTP {res_md.status_code}, Length: {len(res_md.text)} bytes (Validated)")

# 4.2 HTML
res_html = client.get(f"/api/v1/campaigns/{campaign_id}/report?format=html")
assert res_html.status_code == 200
assert "<!DOCTYPE html>" in res_html.text
assert "REVENANT Security Assessment" in res_html.text
print(f"   - HTML: HTTP {res_html.status_code}, Length: {len(res_html.text)} bytes (Validated)")

# 4.3 JSON
res_json = client.get(f"/api/v1/campaigns/{campaign_id}/report?format=json")
assert res_json.status_code == 200
json_report = res_json.json()
assert json_report["campaign_id"] == campaign_id
assert "findings" in json_report
assert "assets" in json_report
print(f"   - JSON: HTTP {res_json.status_code}, Keys: {list(json_report.keys())} (Validated)")

# 4.4 SARIF v2.1.0 -> Strict OASIS Schema Validation
res_sarif = client.get(f"/api/v1/campaigns/{campaign_id}/report?format=sarif")
assert res_sarif.status_code == 200
sarif_data = res_sarif.json()
print(f"   - SARIF: HTTP {res_sarif.status_code}, Version: {sarif_data.get('version')}")

print("   Validating SARIF against official OASIS SARIF 2.1.0 JSON Schema...")
with open("reporting/sarif-schema-2.1.0.json", "r", encoding="utf-8") as sf:
    oasis_schema = json.load(sf)

jsonschema.validate(instance=sarif_data, schema=oasis_schema)
print("   -> STRICT VALIDATION PASSED: Output 100% compliant with OASIS SARIF v2.1.0 standard!")

print("\n=== ALL MILESTONE 4 AUDIT CHECKS PASSED SUCCESSFULLY ===")
