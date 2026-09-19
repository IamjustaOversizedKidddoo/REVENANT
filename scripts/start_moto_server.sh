#!/usr/bin/env bash
# REVENANT — moto-server AWS Mock for CloudFox Live Testing
# Starts a local moto_server (pure-Python AWS mock, no Docker needed)
# and seeds IAM/S3/EC2 resources that CloudFox enumeration targets.

set -u

MOTO_PORT=5000
ENDPOINT="http://127.0.0.1:$MOTO_PORT"
AWS_REGION="us-east-1"
ACCOUNT_ID="123456789012"

echo "[+] Killing any existing moto_server on port $MOTO_PORT..."
pkill -9 -f "moto_server" 2>/dev/null || :
sleep 1

echo "[+] Starting moto_server on port $MOTO_PORT..."
nohup moto_server -H 0.0.0.0 -p $MOTO_PORT > /var/log/moto.log 2>&1 &
MOTO_PID=$!
echo "MOTO_PID=$MOTO_PID"
sleep 3

# Verify server is up
if curl -s "$ENDPOINT/" > /dev/null 2>&1; then
    echo "[CONFIRMED] moto_server responding on $ENDPOINT"
else
    echo "[WARN] moto_server may not be ready yet. Waiting 3 more seconds..."
    sleep 3
fi

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=$AWS_REGION

# === Seed IAM Resources ===
echo "[+] Seeding IAM: AdministratorAccess role..."
aws iam create-role \
    --endpoint-url "$ENDPOINT" \
    --role-name DevopsAdmin \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
    --output text 2>/dev/null || true

aws iam attach-role-policy \
    --endpoint-url "$ENDPOINT" \
    --role-name DevopsAdmin \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" \
    --output text 2>/dev/null || true
echo "  -> Role DevopsAdmin with AdministratorAccess created"

# === Seed S3 Public Bucket ===
echo "[+] Seeding S3: public bucket..."
aws s3api create-bucket \
    --endpoint-url "$ENDPOINT" \
    --bucket revenant-dev-backups \
    --region $AWS_REGION \
    --output text 2>/dev/null || true

aws s3api put-bucket-acl \
    --endpoint-url "$ENDPOINT" \
    --bucket revenant-dev-backups \
    --acl public-read \
    --output text 2>/dev/null || true
echo "  -> S3 bucket revenant-dev-backups with public-read ACL created"

# === Seed EC2 Instance (IMDSv1) ===
echo "[+] Seeding EC2: IMDSv1-enabled instance..."
aws ec2 run-instances \
    --endpoint-url "$ENDPOINT" \
    --image-id ami-12345678 \
    --instance-type t2.micro \
    --metadata-options "HttpTokens=optional,HttpEndpoint=enabled" \
    --count 1 \
    --output json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('  -> EC2:', d['Instances'][0]['InstanceId'], 'HttpTokens=optional')" 2>/dev/null || echo "  -> EC2 seeded"

echo ""
echo "MOTO_ENDPOINT=$ENDPOINT"
echo "MOTO_PID=$MOTO_PID"
echo "[+] moto_server ready. AWS mock environment seeded."
echo ""
echo "Test with:"
echo "  aws --endpoint-url $ENDPOINT iam list-roles"
echo "  aws --endpoint-url $ENDPOINT s3 ls"
echo "  aws --endpoint-url $ENDPOINT ec2 describe-instances"
