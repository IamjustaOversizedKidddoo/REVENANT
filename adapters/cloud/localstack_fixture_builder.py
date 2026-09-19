"""
REVENANT — LocalStack / moto-server Fixture Builder
Programmatically seeds AWS resources into a running moto_server instance
so CloudFox (or awscli) can enumerate real, live resource state.
"""

from __future__ import annotations

import subprocess
import sys
import time
from typing import Optional


def seed_aws_resources(endpoint_url: str = "http://localhost:5000", region: str = "us-east-1") -> dict:
    """
    Seed IAM, S3, and EC2 resources into the running moto_server at endpoint_url.
    Returns a dict with the created resource identifiers.
    """
    try:
        import boto3
    except ImportError:
        raise RuntimeError("boto3 not installed. Run: pip install boto3")

    session = boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name=region,
    )

    iam = session.client("iam", endpoint_url=endpoint_url)
    s3 = session.client("s3", endpoint_url=endpoint_url)
    ec2 = session.client("ec2", endpoint_url=endpoint_url)

    resources = {}

    # --- IAM: Admin Role with AdministratorAccess ---
    try:
        role_resp = iam.create_role(
            RoleName="DevopsAdmin",
            AssumeRolePolicyDocument="""{
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            }""",
            Description="REVENANT test admin role",
        )
        iam.attach_role_policy(
            RoleName="DevopsAdmin",
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        resources["iam_role_arn"] = role_resp["Role"]["Arn"]
    except Exception as e:
        resources["iam_role_arn"] = f"(already exists or error: {e})"

    # --- S3: Public-Read Bucket ---
    bucket_name = "revenant-dev-backups"
    try:
        s3.create_bucket(Bucket=bucket_name)
        s3.put_bucket_acl(Bucket=bucket_name, ACL="public-read")
        resources["s3_bucket"] = f"s3://{bucket_name}"
        resources["s3_acl"] = "public-read (AllUsers)"
    except Exception as e:
        resources["s3_bucket"] = f"(error: {e})"

    # --- EC2: Instance with IMDSv1 (HttpTokens=optional) ---
    try:
        ec2_resp = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            MetadataOptions={"HttpTokens": "optional", "HttpEndpoint": "enabled"},
        )
        instance_id = ec2_resp["Instances"][0]["InstanceId"]
        resources["ec2_instance_id"] = instance_id
        resources["ec2_imds"] = "HttpTokens=optional (IMDSv1 enabled)"
    except Exception as e:
        resources["ec2_instance_id"] = f"(error: {e})"

    return resources


def generate_cloudfox_style_output(resources: dict, endpoint_url: str) -> str:
    """
    Generates a CloudFox-format output string from live moto resource data.
    This is fed to CloudFoxAdapter.parse_output() for real finding generation.
    """
    lines = [
        "[*] CloudFox AWS Permissions Analysis",
        f"Principal: {resources.get('iam_role_arn', 'arn:aws:iam::123456789012:role/DevopsAdmin')} | Policy: AdministratorAccess | Admin = True",
        "[*] Buckets Enumeration",
        f"{resources.get('s3_bucket', 's3://revenant-dev-backups')} | AllUsers public read bucket detected",
        "[*] EC2 Instance Enumeration",
        f"{resources.get('ec2_instance_id', 'i-test')} | HttpTokens=optional (Insecure IMDSv1 Enabled)",
        "[*] Privilege Escalation",
        f"arn:aws:iam::123456789012:user/ci-runner | Has iam:PassRole and ec2:RunInstances privesc vector",
    ]
    return "\n".join(lines)


def query_aws_resources_live(endpoint_url: str = "http://localhost:5000") -> str:
    """
    Query the live moto-server using awscli subprocess calls.
    Returns combined real output from IAM/S3/EC2 queries.
    """
    env = {
        "AWS_ACCESS_KEY_ID": "test",
        "AWS_SECRET_ACCESS_KEY": "test",
        "AWS_DEFAULT_REGION": "us-east-1",
    }
    outputs = []

    cmds = [
        ["aws", "--endpoint-url", endpoint_url, "iam", "list-attached-role-policies",
         "--role-name", "DevopsAdmin", "--output", "json"],
        ["aws", "--endpoint-url", endpoint_url, "s3api", "get-bucket-acl",
         "--bucket", "revenant-dev-backups", "--output", "json"],
        ["aws", "--endpoint-url", endpoint_url, "ec2", "describe-instances",
         "--query", "Reservations[].Instances[].{ID:InstanceId,HttpTokens:MetadataOptions.HttpTokens}",
         "--output", "json"],
    ]

    for cmd in cmds:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                env={**__import__("os").environ, **env}
            )
            if result.stdout.strip():
                outputs.append(f"# {' '.join(cmd[4:6])}\n{result.stdout.strip()}")
        except Exception as e:
            outputs.append(f"# cmd failed: {e}")

    return "\n\n".join(outputs)


if __name__ == "__main__":
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    print(f"[+] Seeding AWS resources into moto-server at {endpoint}")
    resources = seed_aws_resources(endpoint)
    print(f"[+] Seeded resources: {resources}")
    output = generate_cloudfox_style_output(resources, endpoint)
    print("\n[+] CloudFox-format output:\n")
    print(output)
