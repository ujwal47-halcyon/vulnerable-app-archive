# Web CTF notes

Deliberately vulnerable web apps that I run on my own machine to practise web security. All of them are meant for localhost only.

## Labs

| Folder | What it practises |
|---|---|
| `autoelite-xss-lab` | XSS on a car dealership site |
| `cloudpeak-ctf-2026` | IDOR on a cloud hosting SaaS |
| `medilink-ctf-20261` | 10 bugs in a telehealth portal: authentication, access control, rate limiting, XSS including DOM XSS |
| `nexuscloud-ctf-2026` | Stored XSS where only the browser checks the input |
| `novabank` | Banking portal bugs in 2FA, OTP handling, CAPTCHA, account recovery and clickjacking |
| `pizzakingdom` | A pizza ordering site for general web pentest practice |
| `aws-privesc-lab` | Unfinished, templates only |

Each lab has its own README with setup steps. The solution notes live in `SOLUTION_GUIDE.md`, `SPOILERS.md` or `VULNERABILITIES.md`, so don't open those before you try the lab.

The AWS IAM privilege escalation lab is in my [AWS notes repo](https://github.com/ujwal47-halcyon/aws-security-research).

## Please don't

Don't deploy any of these on a public server or a network you don't control. The bugs are there on purpose.
