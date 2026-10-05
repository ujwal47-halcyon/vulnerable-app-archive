# How to Publish Your Cloud Security Labs to GitHub

## ✅ Should You Post Your Labs?
**Yes!** Publishing your hands-on labs to a public (or private) GitHub repository is an excellent way to:
- Demonstrate practical cloud security skills to recruiters and hiring managers
- Build a portfolio of reproducible, CLI-first security exercises
- Contribute to the community by sharing lab setups others can run
- Track your own learning progress over time

## 📂 What to Commit Each Day
For each day of your cloud security journey, commit:
1. **Lab setup scripts** (bash/Python) that create the vulnerable environment
2. **Solution/exploit scripts** showing how you identified and fixed the issue
3. **Write-up/README** detailing:
   - The vulnerability (what was misconfigured)
   - How you discovered it (CLI commands used)
   - The exploitation steps (if it was a CTF-style lab)
   - Remediation (how you would fix it in production)
4. **Any notes or reflections** on what you learned

### Example Daily Commit Structure
```
cloud-security-labs/
├─ day-01-root-hardening/
│  ├─ setup.sh
│  ├─ audit_root_account.py
│  └─ README.md
├─ day-02-billing-alarms/
│  ├─ create_billing_alarm.sh
│  └─ cost_guardrails.md
├─ day-03-iam-privesc-ctf/     ← This lab
│  ├─ README.md
│  ├─ setup.sh
│  ├─ cleanup.sh
│  └─ exploit.py   ← Optional: Python version of the exploit
└─ day-04-s3-public-access/
   ├─ test_s3_bucket.py
   └─ hardening_guide.md
```

## 🔧 How to Set Up the Repository
1. **Create a new repository** on GitHub (e.g., `cloud-security-labs` or `aws-security-ctfs`)
2. **Clone it locally**:
   ```bash
   git clone https://github.com/your-username/cloud-security-labs.git
   cd cloud-security-labs
   ```
3. **Copy your lab folder** into the repository:
   ```bash
   cp -r "C:/Users/Ujwal/Downloads/Cloud Security/IAM/Lab/iam-privesc-ctf" ./day-03-iam-privesc-ctf
   ```
4. **Add, commit, and push**:
   ```bash
   git add day-03-iam-privesc-ctf/
   git commit -m "Day 3: IAM Privilege Escalation CTF Lab - The Rogue Developer's Backdoor"
   git push origin main
   ```

## 📝 Commit Message Best Practices
- Use the format: `"Day X: [Lab Title] - [Brief Description]"`
- Keep messages under 72 characters for the first line
- Add a detailed body if needed (wrap at 72 characters)
- Example:
  ```
  Day 3: IAM Privilege Escalation CTF Lab - The Rogue Developer's Backdoor

  - Created vulnerable policy allowing iam:CreateAccessKey on admin-service-account
  - Demonstrated privilege escalation via AWS CLI simulator and actual exploit
  - Included setup/cleanup scripts and detailed README with vulnerability analysis
  ```

## 🛡️ What NOT to Commit
- **Never commit actual AWS access keys, secret keys, or session tokens**
- Avoid committing `.aws/` directories or files containing credentials
- If you accidentally commit credentials, **revoke them immediately** and rotate keys
- Consider adding a `.gitignore` file to exclude:
  ```
  .aws/
  *.csv
  *.json  # if it might contain secrets from lab output
  credentials/
  ```

## 🌟 Making Your Labs Stand Out
1. **Include a one-liner badge** in your README showing lab status (e.g., "✅ Day 3 Complete")
2. **Add a diagram** (ASCII or draw.io) showing the attack flow
3. **Provide both bash and Python versions** of your exploit/audit scripts
4. **Link to AWS documentation** that explains the correct configuration
5. **Note the real-world relevance** (e.g., "This mirrors CVE-2020-XXXXX in [popular service]")

## 🔄 Keeping Your Repo Updated
After each day of work:
```bash
# From your cloud-security-labs repo root
git add .
git status  # Review what you're about to commit
git commit -m "Day X: [Short description]"
git push
```

## 📄 License Recommendation
Add a `LICENSE` file to your repository. For educational security labs, consider:
- **MIT License** (permissive, allows commercial use)
- **Creative Commons CC-BY-4.0** (requires attribution)
- **GPL-3.0** (if you want to ensure derivatives remain open)

Example MIT License header in each script:
```bash
#!/usr/bin/env bash
# Copyright (c) 2026 [Your Name]
# Licensed under the MIT License (see LICENSE file for details)
```

---

Start your repository today and push your Day 3 lab. Tomorrow, you’ll add Day 4, and so on—building a growing portfolio that shows progression from fundamentals to advanced cloud security techniques.

Happy committing!