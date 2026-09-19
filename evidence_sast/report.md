# REVENANT Security Assessment Report

**Target:** `tests/fixtures/vulnerable_repo`  
**Campaign ID:** `32f26549-a441-4c21-b16e-c1075d5d5f7a`  
**Date:** 2026-09-17T11:54:45.068602+00:00  
**Total Discovered Assets:** 1  
**Total Findings:** 6  

---

## Executive Summary

REVENANT completed an automated security assessment against `tests/fixtures/vulnerable_repo`.

| Severity | Count |
|:---|:---:|
| 🔴 CRITICAL | 4 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 0 |
| 🔵 LOW | 0 |
| ⚪ INFO | 0 |

---

## Discovered Assets (1)

- **vulnerable_repo**

---

## Detailed Findings

### 1. [CRITICAL] Candidate Secret Detected: SlackWebhook (CWE-798)
- **Target / Endpoint:** `tests/fixtures/vulnerable_repo/D:\REVENANT\tests\fixtures\vulnerable_repo\config.py:6`
- **Tool:** `trufflehog`
- **Description:** TruffleHog detected candidate secret of type 'SlackWebhook' in 'D:\REVENANT\tests\fixtures\vulnerable_repo\config.py' at line 6.
- **Code Location:** `D:\REVENANT\tests\fixtures\vulnerable_repo\config.py:6`
- **Snippet:** `Detector: SlackWebhook | Redacted: htt...XXX`
- **Reproduction:**
  ```bash
  trufflehog filesystem tests/fixtures/vulnerable_repo --no-update
  ```
- **Evidence:**
  ```text
  Detector: SlackWebhook
Verified: False
File: D:\REVENANT\tests\fixtures\vulnerable_repo\config.py:6
Redacted: htt...XXX
  ```

### 2. [CRITICAL] SAST Vulnerability: SQL Injection via String Formatting (CWE-89)
- **Target / Endpoint:** `tests/fixtures/vulnerable_repo/database.py:5`
- **Tool:** `semgrep`
- **Description:** SQL query is dynamically constructed using f-string or string concatenation, leading to SQL Injection.
- **Code Location:** `database.py:5`
- **Snippet:** `query = f"SELECT id, username, email FROM users WHERE username = '{username}'"`
- **Reproduction:**
  ```bash
  # Examine database.py line 5:
query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
  ```
- **Evidence:**
  ```text
  File: database.py:5
Rule: revenant.sqli.raw-string-interpolation
Code: query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
  ```

### 3. [CRITICAL] SAST Vulnerability: Command Injection via os.system / subprocess (CWE-78)
- **Target / Endpoint:** `tests/fixtures/vulnerable_repo/server.py:7`
- **Tool:** `semgrep`
- **Description:** Operating system command executed with unescaped shell inputs, allowing arbitrary Remote Code Execution.
- **Code Location:** `server.py:7`
- **Snippet:** `return os.system(f"ping -n 1 {host}")`
- **Reproduction:**
  ```bash
  # Examine server.py line 7:
return os.system(f"ping -n 1 {host}")
  ```
- **Evidence:**
  ```text
  File: server.py:7
Rule: revenant.command-injection.os-system
Code: return os.system(f"ping -n 1 {host}")
  ```

### 4. [CRITICAL] SAST Vulnerability: Insecure Deserialization via pickle.loads (CWE-502)
- **Target / Endpoint:** `tests/fixtures/vulnerable_repo/server.py:11`
- **Tool:** `semgrep`
- **Description:** Untrusted data deserialized using pickle, which allows arbitrary code execution via __reduce__.
- **Code Location:** `server.py:11`
- **Snippet:** `return pickle.loads(cookie_payload)`
- **Reproduction:**
  ```bash
  # Examine server.py line 11:
return pickle.loads(cookie_payload)
  ```
- **Evidence:**
  ```text
  File: server.py:11
Rule: revenant.insecure-deserialization.pickle
Code: return pickle.loads(cookie_payload)
  ```

### 5. [HIGH] Hardcoded Secret Discovered: Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels. (CWE-798)
- **Target / Endpoint:** `tests/fixtures/vulnerable_repo/D:\REVENANT\tests\fixtures\vulnerable_repo\config.py:6`
- **Tool:** `gitleaks`
- **Description:** Gitleaks identified hardcoded secret pattern 'slack-webhook-url' in file 'D:\REVENANT\tests\fixtures\vulnerable_repo\config.py' at line 6.
- **Code Location:** `D:\REVENANT\tests\fixtures\vulnerable_repo\config.py:6`
- **Snippet:** `Rule: slack-webhook-url | Secret: htt...XXX`
- **Reproduction:**
  ```bash
  gitleaks detect --source=tests/fixtures/vulnerable_repo --no-git
  ```
- **Evidence:**
  ```text
  File: D:\REVENANT\tests\fixtures\vulnerable_repo\config.py:6
Rule: slack-webhook-url
Secret Masked: htt...XXX
Entropy: 3.4009645
  ```

### 6. [HIGH] Candidate Secret Detected: Postgres (CWE-798)
- **Target / Endpoint:** `tests/fixtures/vulnerable_repo/D:\REVENANT\tests\fixtures\vulnerable_repo\config.py:7`
- **Tool:** `trufflehog`
- **Description:** TruffleHog detected candidate secret of type 'Postgres' in 'D:\REVENANT\tests\fixtures\vulnerable_repo\config.py' at line 7.
- **Code Location:** `D:\REVENANT\tests\fixtures\vulnerable_repo\config.py:7`
- **Snippet:** `Detector: Postgres | Redacted: pos...432`
- **Reproduction:**
  ```bash
  trufflehog filesystem tests/fixtures/vulnerable_repo --no-update
  ```
- **Evidence:**
  ```text
  Detector: Postgres
Verified: False
File: D:\REVENANT\tests\fixtures\vulnerable_repo\config.py:7
Redacted: pos...432
  ```
