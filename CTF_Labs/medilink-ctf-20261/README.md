# MediLink Health — 2026 Intermediate Bug Bounty CTF

A realistic-looking telehealth / patient-portal SaaS (Flask, 2026 healthcare UI) wired up as a capture-the-flag.
It has **10 working vulnerabilities** across authentication, access control, rate limiting, and XSS — including DOM XSS.

> ⚠️  **Educational use only.** Run it locally on your own machine. **NEVER deploy to a public server.**

---

## Quick start

```powershell
cd C:\Users\Ujwal\Downloads\Local Testing\medilink-ctf-2026
pip install -r requirements.txt
python app.py
```

**Double-click** `start.bat` for a ready-to-run Windows launcher.

Browse to **http://localhost:5000**

---

## Demo account

| Role | Email | Password |
|------|-------|----------|
| Patient | `jordan@medilink.health` | `Jordan#2026` |
| Staff (Dr.) | `dr.alex@medilink.health` | `M3d1l1nk#2026` |

---

## How the CTF works

- There are **10 flags**, one per vulnerability.
- A flag looks like `MEDILINK{...}`.
- **Flags are delivered two ways**, both auto-register to your persistent progress:

### Path 1 — Server-verifiable exploits
When you trigger a server-side bug that the app can detect (stored XSS signature in rendered output, IDOR access, BAC, brute-force success), the flag appears:
  1. In the HTTP **response header**: `X-Medilink-Flag: MEDILINK{...}`
  2. As a visible **flag toast** on the page
  3. **Auto-registered** to your progress in the vault

Use `curl -i` or your proxy history to see the header — the same skill you'll need on real programs.

### Path 2 — Beacon (for DOM XSS)
Client-side XSS can't be verified by the server, so the general method is:
your payload calls the **beacon endpoint** and the flag is returned as JSON:

```
GET /api/beacon?challenge=dom_xss
→ {"ok":true,"flag":"MEDILINK{...}"}
```

Example DOM XSS payload:
```html
<img src=x onerror="fetch('/api/beacon?challenge=dom_xss').then(r=>r.text()).then(t=>alert(t))">
```

For stored/reflected XSS, the beacon also works — but the server-verifiable path is usually easier.

---

## Progress & persistence

- Your progress is saved in `data/players.json` and **survives restarts forever**.
- The vault shows each challenge as 🔒 pending or ✓ solved.
- A **deadline countdown** is displayed on the vault page: **August 19, 2026**.
- Need more time? Edit `data/deadline.json` to extend — progress is never wiped.
- Lost your browser? Use the **Player ID** shown on the vault to restore progress.

---

## Treat it like an engagement

1. **Map every page, form, and link.** Check for a `robots.txt`. Check for leftover files.
2. **Read every response fully** — raw headers, raw HTML source, comments in the markup.
3. **Read client-side JavaScript.** Hidden form fields and frontend validation are often the real vulnerability.
4. **Test the obvious stuff.** Incrementing IDs, editing cookies, brute-forcing with no lockout.
5. **Think in chains.** One bug often unlocks another.

---

## Where to start

| Recon target | What to do |
|---|---|
| `GET /robots.txt` | Always check first — it lists hidden paths. |
| `GET /company-memo.txt` | Internal HR document — leaked to public. |
| `GET /api/directory` | Public staff directory — leaks IDs and emails. |
| `GET /preview` | A client-side note viewer — read the JavaScript. |
| `PUT /api/profile` | Profile update API — watch what fields it accepts. |

---

## Challenge hints (no spoilers)

| # | Challenge | Hint |
|---|-----------|------|
| 1 | Stored XSS — messages | Anything you message the care team gets stored and shown back to you raw. |
| 2 | Reflected XSS — search | The search page echoes your query right back into the page markup. |
| 3 | IDOR — records | Record IDs are sequential. The detail page may not check who owns them. |
| 4 | IDOR — appointments | Write paths need ownership checks too. |
| 5 | BAC — staff area | A link being hidden is not the same as an endpoint being protected. |
| 6 | Mass assignment | The profile API copies whatever fields you send it. |
| 7 | No rate limit — login | The memo explains the staff password format. No lockout = unlimited tries. |
| 8 | No rate limit — OTP | The second factor is a 4-digit code with no attempt limit. |
| 9 | Auth bypass — reset | Password-reset tokens are generated from things an attacker can know. |
| 10 | DOM XSS — preview | A client-side viewer trusts `location.hash` and writes it to the DOM. |

Stuck? Open `SOLUTION_GUIDE.md` — but try to solve it yourself first.

---

## File structure

```
medilink-ctf-2026/
├── app.py                 ← Flask app, all routes + vulnerabilities
├── requirements.txt       ← Python dependencies
├── start.bat              ← Windows launcher
├── README.md              ← This file
├── SOLUTION_GUIDE.md      ← Full spoiler writeups (open only when stuck)
├── data/
│   ├── secret_key.txt     ← Persisted Flask secret (sessions survive restarts)
│   ├── players.json       ← Solved flags (persistent)
│   ├── deadline.json      ← CTF deadline (extendable)
│   ├── users.json         ← Seeded user accounts
│   ├── records.json       ← Medical records
│   ├── appointments.json  ← Appointment data
│   ├── messages.json      ← Patient messages (stored XSS sink)
│   ├── otps.json          ← Issued OTP codes (transient)
│   └── reset_tokens.json  ← Reset tokens (transient)
├── templates/             ← Jinja2 templates
└── static/style.css       ← Modern 2026 healthcare UI
```

---

## Learning objectives

By completing this CTF you will practise:

- **IDOR enumeration** via sequential IDs (read + write paths)
- **Broken function-level access control** (hidden ≠ protected)
- **Mass assignment / API object property authorization** (OWASP API-3)
- **Password brute-forcing** with no rate limit or lockout
- **OTP brute-forcing** (short numeric code, no cooldown)
- **Predictable password-reset token derivation**
- **Stored XSS** with a beacon/exfil callback pattern
- **Reflected XSS** via unescaped query echo
- **DOM XSS** via `location.hash` → `innerHTML`

These are real vulnerability classes appearing in 2025–2026 bug bounty programs.

---

## Ethical guidelines

- ✅ Run this locally for learning and practice
- ✅ Write up findings as if reporting to a real program
- ✅ Explore all injection points and access-control boundaries
- ❌ Never deploy to a public-facing server
- ❌ Never test these techniques on systems you don't own
- ❌ Never share this with people who may misuse it

---

*Built for security training · MediLink Health is entirely fictional*
