# REVENANT Security Assessment Report

**Target:** `tests/fixtures/ad_identity`  
**Campaign ID:** `510e86ae-6566-4eae-bdad-08ebed26caa5`  
**Date:** 2026-09-17T12:43:08.952936+00:00  
**Total Discovered Assets:** 5  
**Total Findings:** 6  

---

## Executive Summary

REVENANT completed an automated security assessment against `tests/fixtures/ad_identity`.

| Severity | Count |
|:---|:---:|
| 🔴 CRITICAL | 3 |
| 🟠 HIGH | 3 |
| 🟡 MEDIUM | 0 |
| 🔵 LOW | 0 |
| ⚪ INFO | 0 |

---

## Discovered Assets (5)

- **WS-DEV01.REVENANT.LOCAL@REVENANT.LOCAL**
- **SVC_MSSQL@REVENANT.LOCAL**
- **JDOE@REVENANT.LOCAL**
- **ADCS-TEMPLATE-VulnerableUserAuth**
- **ADCS-TEMPLATE-InsecureTemplateACL**

---

## Detailed Findings

### 1. [CRITICAL] Active Directory: Insecure Unconstrained Delegation on Workload (WS-DEV01.REVENANT.LOCAL) (CWE-269)
- **Target / Endpoint:** `REVENANT.LOCAL/WS-DEV01.REVENANT.LOCAL`
- **Tool:** `bloodhound`
- **Description:** Host or service account 'WS-DEV01.REVENANT.LOCAL' is configured with Unconstrained Delegation (TRUSTED_FOR_DELEGATION). Whenever any domain user or administrator authenticates to this host, their Ticket-Granting Ticket (TGT) is stored in memory and can be harvested.
- **Remediation:** Configure Resource-Based Constrained Delegation (RBCD) or Kerberos Constrained Delegation (KCD). Ensure high-privilege administrative accounts are marked 'Account is sensitive and cannot be delegated'.
- **Reproduction:**
  ```bash
  # Inspect Kerberos delegation flags on WS-DEV01.REVENANT.LOCAL:
Get-ADComputer -Identity WS-DEV01.REVENANT.LOCAL -Properties TrustedForDelegation
  ```
- **Evidence:**
  ```text
  Object: WS-DEV01.REVENANT.LOCAL
TrustedForDelegation: True
is_dc: False
  ```

### 2. [CRITICAL] Active Directory: Kerberoastable Privileged Account (SVC_MSSQL@REVENANT.LOCAL) (CWE-521)
- **Target / Endpoint:** `REVENANT.LOCAL/SVC_MSSQL@REVENANT.LOCAL`
- **Tool:** `bloodhound`
- **Description:** Account 'SVC_MSSQL@REVENANT.LOCAL' has a registered Service Principal Name (SPN) with administrative domain privileges. Any authenticated domain user can request a Kerberos TGS ticket and attempt offline brute-force cracking of the service hash.
- **Remediation:** Migrate service to a Group Managed Service Account (gMSA) with 128-character auto-rotated passwords, enforce AES-256 encryption, or remove administrative rights from the SPN account.
- **Reproduction:**
  ```bash
  # Request TGS ticket and export hash:
GetUserSPNs.py REVENANT.LOCAL/user:password -request -spn SVC_MSSQL@REVENANT.LOCAL
  ```
- **Evidence:**
  ```text
  Account: SVC_MSSQL@REVENANT.LOCAL
Domain: REVENANT.LOCAL
has_spn: True
admincount: True
  ```

### 3. [CRITICAL] AD CS Misconfiguration (ESC1): Arbitrary SAN Subject with Client Authentication (VulnerableUserAuth) (CWE-295)
- **Target / Endpoint:** `ADCS/VulnerableUserAuth:ESC1`
- **Tool:** `certipy`
- **Description:** Certificate template 'VulnerableUserAuth' permits enrollees to supply an arbitrary Subject Alternative Name (SAN), grants Client Authentication EKU, and requires no Certificate Manager approval. Any authenticated domain user can enroll for a certificate requesting Domain Admin identity and authenticate via Kerberos PKINIT.
- **Remediation:** In Certificate Templates Console, edit template 'VulnerableUserAuth': Under 'Subject Name' tab, select 'Build from this Active Directory information', or under 'Issuance Requirements' tab, check 'CA certificate manager approval'.
- **Reproduction:**
  ```bash
  certipy req -u user@domain -p password -target dc.domain -template VulnerableUserAuth -upn administrator@domain
  ```
- **Evidence:**
  ```text
  Template: VulnerableUserAuth
Enrollee Supplies Subject: True
Extended Key Usage: ['Client Authentication', 'Smart Card Logon']
Requires Manager Approval: False
  ```

### 4. [HIGH] Active Directory: AS-REP Roastable Account (JDOE@REVENANT.LOCAL) (CWE-287)
- **Target / Endpoint:** `REVENANT.LOCAL/JDOE@REVENANT.LOCAL`
- **Tool:** `bloodhound`
- **Description:** Account 'JDOE@REVENANT.LOCAL' has Kerberos pre-authentication disabled (DONT_REQ_PREAUTH). Any network attacker can solicit an encrypted AS-REP response from the KDC without supplying credentials and crack the user password offline.
- **Remediation:** Enable Kerberos pre-authentication on account 'JDOE@REVENANT.LOCAL' in Active Directory Users and Computers.
- **Reproduction:**
  ```bash
  # Solicit AS-REP credential hash:
GetNPUsers.py REVENANT.LOCAL/ -usersfile accounts.txt -format hashcat
  ```
- **Evidence:**
  ```text
  Account: JDOE@REVENANT.LOCAL
Domain: REVENANT.LOCAL
dont_req_preauth: True
  ```

### 5. [HIGH] AD CS Misconfiguration (ESC4): Insecure ACL on Certificate Template (InsecureTemplateACL) (CWE-284)
- **Target / Endpoint:** `ADCS/InsecureTemplateACL:ESC4`
- **Tool:** `certipy`
- **Description:** Certificate template 'InsecureTemplateACL' grants unprivileged domain users write permissions (GenericAll, GenericWrite, or WriteDacl). An unprivileged attacker can modify the template configuration to enable ESC1/ESC2 flags and achieve domain elevation.
- **Remediation:** Remove write and modify permissions for unprivileged groups on certificate template 'InsecureTemplateACL'. Restrict DACL to Domain Admins and Enterprise Admins.
- **Reproduction:**
  ```bash
  # Modify template ACL or properties:
certipy template -u user@domain -p password -target dc.domain -template InsecureTemplateACL -save-old
  ```
- **Evidence:**
  ```text
  Template: InsecureTemplateACL
Insecure Write Rights granted to unprivileged principals.
  ```

### 6. [HIGH] AD CS Misconfiguration (ESC8): NTLM Relayable Web Enrollment Endpoint (REVENANT-CA01) (CWE-287)
- **Target / Endpoint:** `ADCS/REVENANT-CA01:ESC8`
- **Tool:** `certipy`
- **Description:** Certificate Authority 'REVENANT-CA01' exposes an HTTP Web Enrollment endpoint without Extended Protection for Authentication (EPA). An attacker can coerce machine accounts via MS-RPRN (SpoolSample) or PetitPotam and relay NTLM authentication to enroll domain controller certificates.
- **Remediation:** Enable Extended Protection for Authentication (EPA) and require SSL on the AD CS Web Enrollment IIS virtual directory.
- **Reproduction:**
  ```bash
  # Relay coerced NTLM authentication to AD CS:
ntlmrelayx.py -t http://REVENANT-CA01/certsrv/certfnsh.asp -smb2support --adcs
  ```
- **Evidence:**
  ```text
  CA: REVENANT-CA01
Web Enrollment: Enabled
Extended Protection for Authentication: Disabled
  ```
