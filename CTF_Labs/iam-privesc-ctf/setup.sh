#!/usr/bin/env bash
# setup.sh - Creates the IAM privilege escalation CTF lab environment
# Usage: ./setup.sh

set -euo pipefail

# Get AWS Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Using AWS Account ID: $ACCOUNT_ID"

# Create victim user (high-privilege target)
echo "Creating victim user: admin-service-account"
aws iam create-user --user-name admin-service-account > /dev/null

# Create attacker user (low-privilege starting point)
echo "Creating attacker user: dev-rookie"
aws iam create-user --user-name dev-rookie > /dev/null

# Create access keys for attacker user (simulate leaked creds)
echo "Generating access keys for dev-rookie (save these!)"
KEYS=$(aws iam create-access-key --user-name dev-rookie --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
ACCESS_KEY=$(echo "$KEYS" | cut -f1)
SECRET_KEY=$(echo "$KEYS" | cut -f2)
echo "Dev-rookie Access Key ID: $ACCESS_KEY"
echo "Dev-rookie Secret Access Key: $SECRET_KEY"
echo "WARNING: Save these credentials securely - they represent leaked credentials!"

# Create the vulnerable policy
echo "Creating vulnerable IAM policy: CtfVulnerablePolicy"
cat > vulnerable-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BenignDeveloperAccess",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "iam:GetUser"
      ],
      "Resource": "*"
    },
    {
      "Sid": "HiddenPrivEscalation",
      "Effect": "Allow",
      "Action": [
        "iam:CreateAccessKey",
        "iam:TagUser"
      ],
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:user/admin-service-account"
    }
  ]
}
EOF

aws iam create-policy \
    --policy-name CtfVulnerablePolicy \
    --policy-document file://vulnerable-policy.json > /dev/null

# Attach policy to dev-rookie
echo "Attaching CtfVulnerablePolicy to dev-rookie"
aws iam attach-user-policy \
    --user-name dev-rookie \
    --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/CtfVulnerablePolicy > /dev/null

echo ""
echo "=== LAB SETUP COMPLETE ==="
echo "Victim user: admin-service-account"
echo "Attacker user: dev-rookie"
echo "Dev-rookie Access Key ID: $ACCESS_KEY"
echo "Dev-rookie Secret Access Key: $SECRET_KEY"
echo ""
echo "Next steps:"
echo "1. Configure attacker profile:"
echo "   aws configure --profile ctf-attacker"
echo "   (Enter the dev-rookie credentials above)"
echo ""
echo "2. Execute the exploit:"
echo "   aws iam create-access-key --user-name admin-service-account --profile ctf-attacker"
echo ""
echo "3. Cleanup when done:"
echo "   ./cleanup.sh"
echo ""