# Web Security and CTF Notes

Notes from web security practice and CTF-style exercises. The repository includes practice labs across web security and cloud security, alongside my main focus on AWS security.

## Learning order

### 1. Authentication and access control

- Authentication bypass
- Broken access control
- Insecure direct object references (IDOR)

### 2. Request handling

- Missing or weak rate limiting
- Reviewing how applications handle repeated requests

### 3. Cross-site scripting

- XSS basics
- Reflected XSS
- Stored XSS
- Other XSS exercises from practice labs

### 4. Cloud security labs

The `CTF_Labs` directory also contains AWS and IAM privilege-escalation practice. Work through these only in the intended lab environment and keep the notes specific to the exercise.

## Repository layout

- [CTF labs](CTF_Labs/) — individual practice exercises, including web and cloud security labs

## Lab write-up format

For each exercise, record what is available:

1. **Objective:** What the exercise covers
2. **Setup:** The authorised lab environment
3. **Steps:** How the issue was reproduced
4. **Result:** What happened during the test
5. **Impact:** Why the issue matters
6. **Remediation:** How the application or configuration could be fixed

Keep each write-up tied to the actual lab. Do not present practice exercises as findings from real-world targets.

## Scope

Use these techniques only in intentionally vulnerable labs, CTFs or systems where testing is explicitly authorised.

## About

I'm a BCA Cybersecurity and Digital Forensics student at REVA University. I'm learning web security alongside AWS cloud security and documenting the topics I practise.
