# REVENANT Security Assessment Report

**Target:** `http://127.0.0.1:3000`  
**Campaign ID:** `1a02aa85-e09d-4e97-8266-25b76a839a78`  
**Date:** 2026-09-17T09:12:49.713164+00:00  
**Total Discovered Assets:** 1  
**Total Findings:** 5  

---

## Executive Summary

REVENANT completed an automated security assessment against `http://127.0.0.1:3000`.

| Severity | Count |
|:---|:---:|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 0 |
| 🔵 LOW | 0 |
| ⚪ INFO | 3 |

---

## Discovered Assets (1)

- **http://127.0.0.1:3000** (127.0.0.1)
  - Ports: 3000/tcp (http)
  - Endpoints (1):
    - `http://127.0.0.1:3000` [200]

---

## Detailed Findings

### 1. [HIGH] Codeigniter - .env File Discovery (cwe-552)
- **Target / Endpoint:** `http://127.0.0.1:3000/.env`
- **Tool:** `nuclei`
- **Description:** Codeigniter .env file was discovered.
- **Reproduction:**
  ```bash
  curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36' 'http://127.0.0.1:3000/.env'
  ```
- **Evidence:**
  ```text
  Reproduction:
curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36' 'http://127.0.0.1:3000/.env'
  ```

### 2. [HIGH] Generic Env File Disclosure (cwe-552)
- **Target / Endpoint:** `http://127.0.0.1:3000/.env`
- **Tool:** `nuclei` | CVSS: 8.3
- **Description:** A .env file was discovered containing sensitive information like database credentials and tokens. It should not be publicly accessible.

- **Reproduction:**
  ```bash
  curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0' 'http://127.0.0.1:3000/.env'
  ```
- **Evidence:**
  ```text
  Reproduction:
curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0' 'http://127.0.0.1:3000/.env'
  ```

### 3. [INFO] Technologies Detected on http://127.0.0.1:3000
- **Target / Endpoint:** `http://127.0.0.1:3000`
- **Tool:** `httpx`
- **Description:** HTTP probing fingerprinted technologies: Python:3.14.7, BaseHTTP/0.6 Python/3.14.7 Sanctioned-Lab/1.0 Express/4.18.2
- **Evidence:**
  ```text
  Status: 200, Title: 'OWASP Juice Shop / crAPI Lab', Tech: ['Python:3.14.7', 'BaseHTTP/0.6 Python/3.14.7 Sanctioned-Lab/1.0 Express/4.18.2']
  ```

### 4. [INFO] OpenAPI - Detect (cwe-200)
- **Target / Endpoint:** `http://127.0.0.1:3000/openapi.json`
- **Tool:** `nuclei`
- **Description:** OpenAPI was detected.
- **Reproduction:**
  ```bash
  curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15' 'http://127.0.0.1:3000/openapi.json'
  ```
- **Evidence:**
  ```text
  Reproduction:
curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15' 'http://127.0.0.1:3000/openapi.json'
  ```

### 5. [INFO] HTTP Missing Security Headers (cwe-693)
- **Target / Endpoint:** `http://127.0.0.1:3000`
- **Tool:** `nuclei`
- **Description:** This template searches for missing HTTP security headers. The impact of these missing headers can vary.

- **Reproduction:**
  ```bash
  curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (CentOS; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36' 'http://127.0.0.1:3000'
  ```
- **Evidence:**
  ```text
  Reproduction:
curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (CentOS; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36' 'http://127.0.0.1:3000'
  ```
