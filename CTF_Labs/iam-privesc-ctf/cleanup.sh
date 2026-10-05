#!/usr/bin/env bash
# cleanup.sh - Removes all resources created by setup.sh
# Usage: ./cleanup.sh

set -euo pipefail

# Get AWS Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Using AWS Account ID: $ACCOUNT_ID"

# Detach policy from dev-rookie (if exists)
echo "Detaching policy from dev-rookie (if attached)..."
aws iam detach-user-policy \
    --user-name dev-rookie \
    --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/CtfVulnerablePolicy 2>/dev/null || true

# Delete access keys for dev-rookie (if any)
echo "Deleting access keys for dev-rookie (if any)..."
aws iam list-access-keys --user-name dev-rookie --query 'AccessKeyMetadata[*].AccessKeyId' --output text | while read -r key; do
    if [ -n "$key" ]; then
        echo "Deleting access key: $key"
        aws iam delete-access-key --user-name dev-rookie --access-key-id "$key"
    fi
done

# Delete the users
echo "Deleting users: dev-rookie and admin-service-account"
aws iam delete-user --user-name dev-rookie 2>/dev/null || true
aws iam delete-user --user-name admin-service-account 2>/dev/null || true

# Delete the policy
echo "Deleting policy: CtfVulnerablePolicy"
aws iam delete-policy --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/CtfVulnerablePolicy 2>/dev/null || true

# Clean up local policy file
if [ -f vulnerable-policy.json ]; then
    echo "Removing local vulnerable-policy.json"
    rm vulnerable-policy.json
fi

echo "=== CLEANUP COMPLETE ==="