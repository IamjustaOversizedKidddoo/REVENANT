# REVENANT Security Assessment Report

**Target:** `tests/fixtures/cloud_iac`  
**Campaign ID:** `1057c446-ab68-4f94-aeb7-fc75f4940e48`  
**Date:** 2026-09-17T12:32:38.461923+00:00  
**Total Discovered Assets:** 1  
**Total Findings:** 9  

---

## Executive Summary

REVENANT completed an automated security assessment against `tests/fixtures/cloud_iac`.

| Severity | Count |
|:---|:---:|
| 🔴 CRITICAL | 5 |
| 🟠 HIGH | 3 |
| 🟡 MEDIUM | 1 |
| 🔵 LOW | 0 |
| ⚪ INFO | 0 |

---

## Discovered Assets (1)

- **cloud_iac**

---

## Detailed Findings

### 1. [CRITICAL] Hardcoded Credential in Dockerfile Directive (CWE-798)
- **Target / Endpoint:** `tests/fixtures/cloud_iac/Dockerfile:7`
- **Tool:** `trivy`
- **Description:** Dockerfile embeds sensitive credential or token directly into layer metadata via ENV or ARG directive.
- **Remediation:** Inject secrets dynamically at runtime using secret stores or BuildKit '--mount=type=secret'.
- **Code Location:** `Dockerfile:7`
- **Snippet:** `ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"`
- **Reproduction:**
  ```bash
  # Examine Dockerfile line 7:
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
  ```
- **Evidence:**
  ```text
  File: Dockerfile:7
Code: ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
  ```

### 2. [CRITICAL] Hardcoded Credential in Dockerfile Directive (CWE-798)
- **Target / Endpoint:** `tests/fixtures/cloud_iac/Dockerfile:8`
- **Tool:** `trivy`
- **Description:** Dockerfile embeds sensitive credential or token directly into layer metadata via ENV or ARG directive.
- **Remediation:** Inject secrets dynamically at runtime using secret stores or BuildKit '--mount=type=secret'.
- **Code Location:** `Dockerfile:8`
- **Snippet:** `ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
- **Reproduction:**
  ```bash
  # Examine Dockerfile line 8:
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  ```
- **Evidence:**
  ```text
  File: Dockerfile:8
Code: ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  ```

### 3. [CRITICAL] Cloud Misconfiguration: Publicly Readable S3 Bucket (CIS-2.1.5) (CWE-732)
- **Target / Endpoint:** `tests/fixtures/cloud_iac/terraform_aws.tf:18`
- **Tool:** `prowler`
- **Description:** AWS S3 bucket resource configures public read/write ACL, allowing unauthenticated Internet access to bucket data.
- **Remediation:** Set S3 bucket ACL to 'private' and configure aws_s3_bucket_public_access_block with block_public_acls = true.
- **Code Location:** `terraform_aws.tf:18`
- **Snippet:** `acl    = "public-read"`
- **Reproduction:**
  ```bash
  # Examine terraform_aws.tf line 18:
acl    = "public-read"
  ```
- **Evidence:**
  ```text
  File: terraform_aws.tf:18
Misconfiguration: acl    = "public-read"
  ```

### 4. [CRITICAL] Cloud Misconfiguration: Overly Permissive Wildcard IAM Policy (CIS-1.16) (CWE-250)
- **Target / Endpoint:** `tests/fixtures/cloud_iac/terraform_aws.tf:56`
- **Tool:** `prowler`
- **Description:** IAM policy statement grants full administrative privileges ('Action': '*', 'Resource': '*'), violating the principle of least privilege.
- **Remediation:** Scope IAM actions and resources strictly to the required service operations and specific resource ARNs.
- **Code Location:** `terraform_aws.tf:56`
- **Snippet:** `Action   = "*"`
- **Reproduction:**
  ```bash
  # Examine terraform_aws.tf line 56:
Action   = "*"
  ```
- **Evidence:**
  ```text
  File: terraform_aws.tf:56
Policy defines Action: '*' and Resource: '*'
  ```

### 5. [CRITICAL] Kubernetes Misconfiguration: Privileged Container Execution (CIS-5.2) (CWE-250)
- **Target / Endpoint:** `tests/fixtures/cloud_iac/k8s_deployment.yaml:25`
- **Tool:** `prowler`
- **Description:** Pod specification declares 'securityContext.privileged: true', disabling container isolation and granting host kernel capabilities.
- **Remediation:** Set 'securityContext.privileged: false' and enforce Pod Security Admission standards.
- **Code Location:** `k8s_deployment.yaml:25`
- **Snippet:** `privileged: true`
- **Reproduction:**
  ```bash
  # Examine k8s_deployment.yaml line 25:
privileged: true
  ```
- **Evidence:**
  ```text
  File: k8s_deployment.yaml:25
Privileged container enabled: privileged: true
  ```

### 6. [HIGH] Container Misconfiguration: Process Runs as Root User (CWE-250)
- **Target / Endpoint:** `tests/fixtures/cloud_iac/Dockerfile:1`
- **Tool:** `trivy`
- **Description:** Container execution environment runs with root privileges by default (missing non-root USER instruction), increasing the blast radius of container escape exploits.
- **Remediation:** Create a dedicated unprivileged user and declare 'USER <username_or_uid>' before ENTRYPOINT.
- **Code Location:** `Dockerfile:1`
- **Snippet:** `# Insecure Test Dockerfile for Container Security Auditing`
- **Reproduction:**
  ```bash
  # Examine Dockerfile: Missing non-root USER directive.
  ```
- **Evidence:**
  ```text
  File: Dockerfile
Status: Last specified user is 'root'.
  ```

### 7. [HIGH] Cloud Misconfiguration: Ingress Open to Internet (0.0.0.0/0) (CIS-4.1) (CWE-284)
- **Target / Endpoint:** `tests/fixtures/cloud_iac/terraform_aws.tf:43`
- **Tool:** `prowler`
- **Description:** Security group allows unrestricted inbound access (0.0.0.0/0) on administrative or database ports.
- **Remediation:** Restrict ingress CIDRs to corporate VPN subnets or private bastion hosts.
- **Code Location:** `terraform_aws.tf:43`
- **Snippet:** `cidr_blocks = ["0.0.0.0/0"]`
- **Reproduction:**
  ```bash
  # Examine terraform_aws.tf line 43:
cidr_blocks = ["0.0.0.0/0"]
  ```
- **Evidence:**
  ```text
  File: terraform_aws.tf:43
Misconfiguration: Ingress open to 0.0.0.0/0
  ```

### 8. [HIGH] Kubernetes Misconfiguration: Host Network Namespace Shared (CWE-250)
- **Target / Endpoint:** `tests/fixtures/cloud_iac/k8s_deployment.yaml:19`
- **Tool:** `prowler`
- **Description:** Pod specification enables 'hostNetwork: true', allowing container to snoop and bind directly to host network interfaces.
- **Remediation:** Remove 'hostNetwork: true' to isolate pod traffic inside container virtual networking.
- **Code Location:** `k8s_deployment.yaml:19`
- **Snippet:** `hostNetwork: true`
- **Reproduction:**
  ```bash
  # Examine k8s_deployment.yaml line 19:
hostNetwork: true
  ```
- **Evidence:**
  ```text
  File: k8s_deployment.yaml:19
Host network shared: hostNetwork: true
  ```

### 9. [MEDIUM] Container Misconfiguration: Mutable Base Image Tag (:latest) (CWE-1188)
- **Target / Endpoint:** `tests/fixtures/cloud_iac/Dockerfile:2`
- **Tool:** `trivy`
- **Description:** Base container image uses mutable ':latest' tag or omits version tag, leading to non-deterministic builds and supply-chain drift.
- **Remediation:** Pin the base image to an immutable version tag or digest (e.g., node:20-alpine@sha256:...).
- **Code Location:** `Dockerfile:2`
- **Snippet:** `FROM node:latest`
- **Reproduction:**
  ```bash
  # Examine Dockerfile line 2:
FROM node:latest
  ```
- **Evidence:**
  ```text
  File: Dockerfile:2
Code: FROM node:latest
  ```
