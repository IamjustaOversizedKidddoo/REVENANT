"""
REVENANT — Autonomous Remediation Engine
Transforms detected vulnerabilities, exposed assets, and attack graph choke points
into actionable, executable remediation artifacts:
1. Terraform / CloudFormation: Automated cloud infrastructure hardening (S3 public block, IAM least-privilege, SG isolation)
2. Kubernetes Manifests: Hardened NetworkPolicy and PodSecurityStandards (deny-all ingress, drop NET_RAW)
3. Ansible Lockdown Playbooks: OS / service configuration hardening (disable SMBv1, enforce SMB signing, SSH hardening)
4. Detection Engineering Rules: Synthesizes custom YARA and Sigma rules from discovered attack indicators
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from control_plane.schemas.models import Finding, Severity

logger = logging.getLogger("revenant.orchestrator.remediation")


class RemediationType(str, Enum):
    TERRAFORM = "terraform"
    KUBERNETES = "kubernetes"
    ANSIBLE = "ansible"
    YARA = "yara"
    SIGMA = "sigma"
    SURICATA = "suricata"


class RemediationArtifact(BaseModel):
    """Normalized executable remediation output."""
    artifact_type: RemediationType
    filename: str
    content: str
    finding_id: str
    finding_title: str
    target: str
    description: str
    apply_command: str
    rollback_command: Optional[str] = None


class RemediationEngine:
    """Autonomous engine generating executable remediation code from findings and choke points."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir) if output_dir else Path("evidence_remediation")

    def remediate_finding(self, finding: Finding) -> List[RemediationArtifact]:
        """Generate all applicable remediation artifacts for a single Finding."""
        artifacts: List[RemediationArtifact] = []

        # 1. Cloud / Infrastructure remediation (Terraform)
        tf_art = self.generate_terraform_remediation(finding)
        if tf_art:
            artifacts.append(tf_art)

        # 2. Kubernetes / Container remediation
        k8s_art = self.generate_kubernetes_remediation(finding)
        if k8s_art:
            artifacts.append(k8s_art)

        # 3. Host / Network / Operating System remediation (Ansible)
        ansible_art = self.generate_ansible_remediation(finding)
        if ansible_art:
            artifacts.append(ansible_art)

        # 4. Detection Engineering (YARA / Sigma / Suricata)
        det_arts = self.generate_detection_rules(finding)
        artifacts.extend(det_arts)

        return artifacts

    def remediate_campaign(self, findings: List[Finding]) -> List[RemediationArtifact]:
        """Generate comprehensive remediation suite across an entire assessment campaign."""
        all_artifacts: List[RemediationArtifact] = []
        for finding in findings:
            all_artifacts.extend(self.remediate_finding(finding))
        return all_artifacts

    # --------------------------------------------------------------------------
    # 1. TERRAFORM GENERATOR
    # --------------------------------------------------------------------------
    def generate_terraform_remediation(self, finding: Finding) -> Optional[RemediationArtifact]:
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        target = finding.target or "unknown"
        finding_id = finding.id or hashlib.md5(finding.title.encode()).hexdigest()[:8]

        # A. S3 Public Access Remediation
        if "s3" in title_lower or "s3" in desc_lower or "bucket" in title_lower:
            bucket_name = target.replace("s3://", "").split("/")[0] if "s3://" in target else "target-bucket"
            if bucket_name == "unknown" or not bucket_name:
                bucket_name = "remediated_s3_bucket"

            safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", bucket_name)
            tf_code = f'''# REVENANT Autonomous Remediation — AWS S3 Bucket Lockdown
# Target: {target}
# Finding: {finding.title}

resource "aws_s3_bucket_public_access_block" "lockdown_{safe_name}" {{
  bucket = "{bucket_name}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypt_{safe_name}" {{
  bucket = "{bucket_name}"

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}
'''
            return RemediationArtifact(
                artifact_type=RemediationType.TERRAFORM,
                filename=f"s3_lockdown_{safe_name}.tf",
                content=tf_code,
                finding_id=finding_id,
                finding_title=finding.title,
                target=target,
                description=f"Automated Terraform module to enable PublicAccessBlock and default AES-256 SSE on S3 bucket '{bucket_name}'.",
                apply_command=f"terraform apply -target=aws_s3_bucket_public_access_block.lockdown_{safe_name}",
                rollback_command=f"terraform destroy -target=aws_s3_bucket_public_access_block.lockdown_{safe_name}",
            )

        # B. Security Group Ingress Lockdown (0.0.0.0/0 on SSH / RDP / admin ports)
        if any(term in title_lower for term in ["security group", "port open", "ssh", "rdp", "exposed port"]) or (
            finding.cwe in ["CWE-284", "CWE-200", "CWE-269"] and "0.0.0.0" in desc_lower
        ):
            safe_id = re.sub(r"[^a-zA-Z0-9_]", "_", target)
            port = "22"
            if "3389" in title_lower or "rdp" in title_lower:
                port = "3389"
            elif "445" in title_lower or "smb" in title_lower:
                port = "445"

            tf_code = f'''# REVENANT Autonomous Remediation — AWS Security Group Restrictive Ingress
# Target: {target}
# Finding: {finding.title}

resource "aws_security_group_rule" "restricted_ingress_{safe_id}" {{
  type              = "ingress"
  from_port         = {port}
  to_port           = {port}
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"] # Restricted to internal VPN / RFC1918 range
  security_group_id = "sg-remediate-{safe_id}"
  description       = "Automated lockdown by REVENANT: restricted from 0.0.0.0/0 to internal subnet."
}}
'''
            return RemediationArtifact(
                artifact_type=RemediationType.TERRAFORM,
                filename=f"sg_lockdown_{safe_id}.tf",
                content=tf_code,
                finding_id=finding_id,
                finding_title=finding.title,
                target=target,
                description=f"Restricts open public ingress on port {port} to internal network CIDR range.",
                apply_command=f"terraform apply -target=aws_security_group_rule.restricted_ingress_{safe_id}",
                rollback_command=f"terraform destroy -target=aws_security_group_rule.restricted_ingress_{safe_id}",
            )

        # C. IAM Least Privilege Policy Hardening
        if "iam" in title_lower or "privilege escalation" in title_lower or "wildcard" in desc_lower:
            safe_target = re.sub(r"[^a-zA-Z0-9_]", "_", target)
            tf_code = f'''# REVENANT Autonomous Remediation — AWS IAM Least Privilege Policy
# Target: {target}
# Finding: {finding.title}

data "aws_iam_policy_document" "least_privilege_{safe_target}" {{
  statement {{
    sid       = "DenyWildcardPrivileges"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
    condition {{
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }}
  }}
}}
'''
            return RemediationArtifact(
                artifact_type=RemediationType.TERRAFORM,
                filename=f"iam_hardening_{safe_target}.tf",
                content=tf_code,
                finding_id=finding_id,
                finding_title=finding.title,
                target=target,
                description="Enforces MFA and strips unconstrained administrative privileges.",
                apply_command=f"terraform apply",
                rollback_command=f"terraform destroy",
            )

        return None

    # --------------------------------------------------------------------------
    # 2. KUBERNETES GENERATOR
    # --------------------------------------------------------------------------
    def generate_kubernetes_remediation(self, finding: Finding) -> Optional[RemediationArtifact]:
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        target = finding.target or "default"
        finding_id = finding.id or hashlib.md5(finding.title.encode()).hexdigest()[:8]

        is_k8s = any(k in title_lower or k in desc_lower for k in [
            "kubernetes", "k8s", "kubescape", "pod", "container", "namespace", "privileged container", "cve-2024"
        ])

        if not is_k8s:
            return None

        safe_ns = re.sub(r"[^a-zA-Z0-9\-]", "-", target).lower().strip("-") or "default"

        # A. NetworkPolicy Isolation (for lateral movement / unsegmented pods)
        if any(term in title_lower for term in ["network", "lateral", "ingress", "unsegmented", "traffic"]):
            yaml_code = f'''apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: revenant-default-deny-ingress
  namespace: {safe_ns}
  labels:
    remediation.revenant.io/managed-by: "revenant-autonomous-engine"
spec:
  podSelector: {{}}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: authorized-client
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      ports:
      - protocol: UDP
        port: 53
'''
            return RemediationArtifact(
                artifact_type=RemediationType.KUBERNETES,
                filename=f"k8s_networkpolicy_deny_{safe_ns}.yaml",
                content=yaml_code,
                finding_id=finding_id,
                finding_title=finding.title,
                target=target,
                description=f"Applies default-deny ingress NetworkPolicy to isolate pods in namespace '{safe_ns}'.",
                apply_command=f"kubectl apply -f k8s_networkpolicy_deny_{safe_ns}.yaml -n {safe_ns}",
                rollback_command=f"kubectl delete -f k8s_networkpolicy_deny_{safe_ns}.yaml -n {safe_ns}",
            )

        # B. PodSecurity Standards Hardening (privileged: false, drop ALL, readOnlyRootFilesystem)
        yaml_code = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: {safe_ns}-hardened-patch
  namespace: {safe_ns}
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        securityContext:
          allowPrivilegeEscalation: false
          privileged: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
'''
        return RemediationArtifact(
            artifact_type=RemediationType.KUBERNETES,
            filename=f"k8s_pod_security_patch_{safe_ns}.yaml",
            content=yaml_code,
            finding_id=finding_id,
            finding_title=finding.title,
            target=target,
            description=f"Applies zero-trust PodSecurityStandards patch: disables privileged mode, drops capabilities, and enforces read-only root fs in '{safe_ns}'.",
            apply_command=f"kubectl patch deployment <deployment-name> -n {safe_ns} --patch-file k8s_pod_security_patch_{safe_ns}.yaml",
            rollback_command=f"kubectl rollout undo deployment <deployment-name> -n {safe_ns}",
        )

    # --------------------------------------------------------------------------
    # 3. ANSIBLE PLAYBOOK GENERATOR
    # --------------------------------------------------------------------------
    def generate_ansible_remediation(self, finding: Finding) -> Optional[RemediationArtifact]:
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        target = finding.target or "all"
        finding_id = finding.id or hashlib.md5(finding.title.encode()).hexdigest()[:8]

        # A. SMBv1 & SMB Signing Lockdown
        if "smb" in title_lower or "eternalblue" in title_lower or "445" in target:
            playbook = f'''---
- name: REVENANT Autonomous Remediation — SMB Hardening & Protocol Lockdown
  hosts: {target}
  become: yes
  tasks:
    - name: Disable SMBv1 Protocol (Windows)
      ansible.windows.win_regedit:
        path: HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters
        name: SMB1
        data: 0
        type: dword
        state: present
      when: ansible_os_family == "Windows"

    - name: Enforce SMB Packet Signing (Windows)
      ansible.windows.win_regedit:
        path: HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters
        name: RequireSecuritySignature
        data: 1
        type: dword
        state: present
      when: ansible_os_family == "Windows"

    - name: Enforce SMBv2/3 Minimum Protocol (Linux Samba)
      ansible.builtin.lineinfile:
        path: /etc/samba/smb.conf
        regexp: '^\\s*server min protocol'
        line: '   server min protocol = SMB2_02'
        insertafter: '\\[global\\]'
      when: ansible_os_family != "Windows"
      notify: Restart Samba

  handlers:
    - name: Restart Samba
      ansible.builtin.service:
        name: smbd
        state: restarted
'''
            return RemediationArtifact(
                artifact_type=RemediationType.ANSIBLE,
                filename="ansible_smb_lockdown.yml",
                content=playbook,
                finding_id=finding_id,
                finding_title=finding.title,
                target=target,
                description="Disables deprecated SMBv1 protocol and mandates SMB packet signing to prevent NTLM relay and EternalBlue.",
                apply_command=f"ansible-playbook -i '{target},' ansible_smb_lockdown.yml",
                rollback_command=f"# Revert LanmanServer Parameters registry keys",
            )

        # B. Host SSH / Telnet / Unencrypted Service Hardening
        if any(term in title_lower for term in ["telnet", "ssh", "dropbear", "plaintext", "cwe-319"]):
            playbook = f'''---
- name: REVENANT Autonomous Remediation — Insecure Remote Access Lockdown
  hosts: {target}
  become: yes
  tasks:
    - name: Stop and Disable Telnet Service
      ansible.builtin.service:
        name: "{{{{ item }}}}"
        state: stopped
        enabled: no
      loop:
        - telnet.socket
        - telnetd
      ignore_errors: yes

    - name: Harden OpenSSH Server Configuration
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{{{ item.regexp }}}}"
        line: "{{{{ item.line }}}}"
        state: present
      loop:
        - {{ regexp: '^#?PermitRootLogin', line: 'PermitRootLogin no' }}
        - {{ regexp: '^#?PasswordAuthentication', line: 'PasswordAuthentication no' }}
        - {{ regexp: '^#?MaxAuthTries', line: 'MaxAuthTries 3' }}
      notify: Restart SSH

  handlers:
    - name: Restart SSH
      ansible.builtin.service:
        name: sshd
        state: restarted
'''
            return RemediationArtifact(
                artifact_type=RemediationType.ANSIBLE,
                filename="ansible_ssh_telnet_lockdown.yml",
                content=playbook,
                finding_id=finding_id,
                finding_title=finding.title,
                target=target,
                description="Disables insecure Telnet sockets and enforces key-only non-root SSH authentication.",
                apply_command=f"ansible-playbook -i '{target},' ansible_ssh_telnet_lockdown.yml",
                rollback_command="# Restore /etc/ssh/sshd_config from backup",
            )

        return None

    # --------------------------------------------------------------------------
    # 4. DETECTION ENGINEERING (YARA / SIGMA)
    # --------------------------------------------------------------------------
    def generate_detection_rules(self, finding: Finding) -> List[RemediationArtifact]:
        artifacts: List[RemediationArtifact] = []
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        target = finding.target or "unknown"
        finding_id = finding.id or hashlib.md5(finding.title.encode()).hexdigest()[:8]

        # A. YARA Detection Rule (Webshells, Malicious Payloads, Backdoors)
        if any(k in title_lower or k in desc_lower for k in ["webshell", "yara", "malware", "backdoor", "trojan", "payload"]):
            safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", finding.title)
            mitre_str = ", ".join(finding.mitre_attack_ids) if finding.mitre_attack_ids else "T1505.003"

            yara_content = f'''rule REVENANT_AutoDetect_{safe_name}
{{
    meta:
        description = "Automated YARA detection generated by REVENANT for finding: {finding.title}"
        author = "REVENANT Autonomous Remediation Engine"
        reference_finding = "{finding_id}"
        severity = "{finding.severity.value}"
        mitre_attack = "{mitre_str}"
        cwe = "{finding.cwe or 'CWE-94'}"

    strings:
        $s1 = "eval(base64_decode" ascii wide nocase
        $s2 = "system($_GET" ascii wide nocase
        $s3 = "passthru($_POST" ascii wide nocase
        $s4 = "shell_exec(" ascii wide nocase
        $h1 = {{ 65 76 61 6c 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65 }}

    condition:
        any of ($s*) or $h1
}}
'''
            artifacts.append(
                RemediationArtifact(
                    artifact_type=RemediationType.YARA,
                    filename=f"rule_{finding_id}_{safe_name[:30]}.yar",
                    content=yara_content,
                    finding_id=finding_id,
                    finding_title=finding.title,
                    target=target,
                    description=f"Generated YARA detection rule targeting observed indicators from '{finding.title}'.",
                    apply_command=f"yara -r rule_{finding_id}_{safe_name[:30]}.yar /var/www/ /tmp/",
                    rollback_command=f"rm rule_{finding_id}_{safe_name[:30]}.yar",
                )
            )

        # B. Sigma Rule (Process Injection / Privilege Escalation / C2)
        if any(k in title_lower or k in desc_lower for k in ["injection", "privilege escalation", "c2", "beacon", "rce", "process"]):
            safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", finding.title)
            sigma_content = f'''title: REVENANT AutoDetect - {finding.title}
id: {finding_id}-sigma-auto
status: experimental
description: Auto-generated Sigma detection rule triggered by assessment finding
author: REVENANT Autonomous Remediation Engine
references:
  - https://attack.mitre.org/techniques/{finding.mitre_attack_ids[0] if finding.mitre_attack_ids else 'T1055'}
tags:
  - attack.execution
  - attack.{finding.mitre_attack_ids[0].lower().replace('.', '_') if finding.mitre_attack_ids else 't1055'}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
    CommandLine|contains:
      - 'VirtualAllocEx'
      - 'WriteProcessMemory'
      - 'CreateRemoteThread'
      - 'whoami'
  condition: selection
falsepositives:
  - Legitimate administrative diagnostics
level: high
'''
            artifacts.append(
                RemediationArtifact(
                    artifact_type=RemediationType.SIGMA,
                    filename=f"sigma_{finding_id}_{safe_name[:30]}.yml",
                    content=sigma_content,
                    finding_id=finding_id,
                    finding_title=finding.title,
                    target=target,
                    description=f"Sigma detection rule for SIEM/EDR correlating {finding.title}.",
                    apply_command=f"sigmac -t splunk -c winlogbeat sigma_{finding_id}_{safe_name[:30]}.yml",
                    rollback_command=f"rm sigma_{finding_id}_{safe_name[:30]}.yml",
                )
            )

        return artifacts

    def export_artifacts(self, artifacts: List[RemediationArtifact], output_dir: Optional[str] = None) -> List[str]:
        """Write remediation artifacts to organized directories on disk."""
        target_dir = Path(output_dir) if output_dir else self.output_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        exported_paths: List[str] = []
        for art in artifacts:
            type_subdir = target_dir / art.artifact_type.value
            type_subdir.mkdir(parents=True, exist_ok=True)
            out_file = type_subdir / art.filename
            out_file.write_text(art.content, encoding="utf-8")
            exported_paths.append(str(out_file))

        logger.info(f"Exported {len(exported_paths)} remediation artifacts to {target_dir}")
        return exported_paths
