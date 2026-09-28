# ☁️ CloudPeak — IDOR Training Lab (CTF Edition)

> ⚠️ **FOR LOCAL, AUTHORIZED TRAINING ONLY.** This is a deliberately vulnerable
> cloud-hosting SaaS. **Never deploy it to a public server, cloud, or network you
> don't control.**

CloudPeak is a realistic 2026 managed-cloud hosting platform. It looks and behaves
like a legitimate SaaS — marketing pages, pricing, a customer dashboard, hosting
services, invoices, and a support ticketing portal — but it ships with **two
different kinds of Insecure Direct Object Reference (IDOR, CWE-639)** for
bug-bounty practice.

The theme and bugs model real-world 2026 findings: object references that are
encoded but not secured, resources fetched with no ownership check, and a support
ticket where a customer pasted her **password-reset link** — a classic account-
takeover chain.

---

## 🚀 Quick start

```powershell
cd cloudpeak-ctf-2026
pip install -r requirements.txt
python app.py
```

Or double-click **`start.bat`** on Windows.

Then open **http://localhost:5000**.

### Demo credentials

| Account | Email | Password | Notes |
|---------|-------|----------|-------|
| Demo customer (you) | `alex@cloudpeak.io` | `Cloudpeak#2026` | Starting account for testing |
| Admin (trainer) | `admin@cloudpeak.io` | `admin123` | `/admin` panel + password recovery helper |

You can also **register your own account** on `/signup`.

### First-run behaviour

The `data/` folder is auto-created and seeded on first launch. All state persists
in JSON files across restarts. Delete the folder to reset the lab.

---

## 🎯 The challenges

There are **2 challenges**, both **IDOR (CWE-639)**. Flags look like
`CLOUDPEAK{...}` and are shown on the page you reach by exploiting the bug; the
same response also carries an **`X-Cloudpeak-Flag`** header so you can practice
with `curl`/Burp. Track your progress on **`/challenges`**.

### Challenge 1 — Horizontal IDOR on customer resources (CWE-639)

| | |
|---|---|
| **Location** | `GET /service/<ref>` · `GET /api/service/<id>` · `GET /invoice/<id>` |
| **Reference** | base64 of a sequential integer (e.g. `Mg` → `2`) |
| **Bug** | Resource is fetched by the client-supplied reference with **no ownership check** |
| **Impact** | Read any customer's hosting config, server IPs, SSH users, deployment notes |

### Challenge 2 — Password-reset-token IDOR → account takeover (CWE-639 + CWE-640)

| | |
|---|---|
| **Location** | `GET /support/ticket/<ref>` → `GET /reset/<token>` |
| **Reference** | Tickets are `TKT-1001`, `TKT-1002`, … (sequential) |
| **Bug** | Ticket view has **no ownership check**, and one client disclosed her (still-valid) password-reset link in a ticket; `/reset/<token>` trusts the bare token |
| **Impact** | Read other customers' tickets, steal a reset token, **reset the victim's password → full account takeover** |

> 🕵️ The intended victim is **Priya Sharma** (`priya@cloudpeak.io`). Her support
> ticket `TKT-1005` contains the exact reset link she pasted for support to
> investigate. That's the whole chain.

---

## 🔬 Testing methodology (no spoilers)

1. **Register or log in** as the demo customer.
2. **Explore the dashboard.** Notice the URLs for your services look like
   `/service/NA==`-style tokens. Ask yourself: *what is that token, and does it
   really gate access?*
3. **Decode the reference.** Base64 is easy to spot (`=`-padding, `/`, `+`, short
   token). It decodes to a number.
4. **Enumerate.** Neighbouring references give you *other* customers' data. The
   first flag is sitting in somebody's deployment notes.
5. **Visit Support.** The portal lists only your tickets, but references are
   sequential (`TKT-1001`, `TKT-1002`, …). Walk them.
6. **Find the disclosure.** One ticket contains a customer's password-reset link.
7. **Use the token.** Visit `/reset/<token>`, set a new password for that account,
   sign in as her. The second flag is on her dashboard.

Full step-by-step writeups live in **`SOLUTION_GUIDE.md`** (contains spoilers).

---

## 🏗 Project structure

```
cloudpeak-ctf-2026/
├── app.py                 # Flask app — routes, seed data, both IDORs
├── requirements.txt       # Python dependencies
├── start.bat              # Windows one-click launcher
├── README.md              # This file
├── SOLUTION_GUIDE.md      # Full spoiler writeups
├── templates/             # Jinja2 templates
│   ├── base.html          # Nav + footer shell
│   ├── home.html          # Marketing homepage
│   ├── pricing.html       # Pricing page
│   ├── features.html      # Feature page
│   ├── login.html         # Sign-in
│   ├── signup.html        # Register
│   ├── forgot.html        # Request password reset
│   ├── reset.html         # /reset/<token> (Challenge 2 surface)
│   ├── dashboard.html     # Customer dashboard (flag 2 lives here for Priya)
│   ├── service.html       # Service detail (Challenge 1 surface)
│   ├── invoice.html       # Invoice detail (Challenge 1 surface)
│   ├── support.html       # Support portal (ticket list + create)
│   ├── ticket.html        # Ticket detail (Challenge 2 surface)
│   ├── admin.html         # Trainer admin panel
│   ├── challenges.html    # CTF tracker
│   └── 404.html / 403.html
├── static/
│   └── style.css          # 2026 dark glassmorphism design
└── data/                  # Auto-created JSON storage (users, services,
                           # invoices, tickets, reset_tokens)
```

---

## 🧭 Key routes

| Route | Method | Purpose | Auth |
|-------|--------|---------|------|
| `/` `/pricing` `/features` | GET | Marketing | Public |
| `/signup` `/login` `/logout` | — | Auth | Public |
| `/forgot` | GET/POST | Request reset (link printed to console) | Public |
| `/reset/<token>` | GET/POST | Change password using a token | Public |
| `/dashboard` | GET | Your overview | Login |
| `/service/<ref>` | GET | Service detail — **IDOR #1** | Login |
| `/api/service/<id>` | GET | Service JSON — **IDOR #1 (API)** | Login |
| `/invoice/<id>` | GET | Invoice detail — **IDOR #1** | Login |
| `/support` | GET/POST | Tickets + create | Login |
| `/support/ticket/<ref>` | GET | Ticket detail — **IDOR #2** | Login |
| `/admin` | GET | Trainer panel (admin role) | Admin |
| `/challenges` | GET | Challenge tracker | Public |

---

## 🧠 Learning objectives

- Understand **IDOR vs missing function-level access control** — *what you can
  reach* vs *what you can do*.
- Spot **object references that are encoded but not authorization**: base64
  numbers, sequential ticket IDs, unbound reset tokens.
- Practise **enumeration** (integer/base64/ID ranges) with `curl` or Burp
  Repeater/Intruder.
- Understand how a **client-visible disclosure (reset link in a support ticket)**
  becomes **account takeover** when the reset endpoint trusts the token alone.
- Practise reading `X-*` response headers for flags and writing it all up as a
  real bug report.

---

## 🛠 How to fix (remediation, for learning)

**1. Enforce ownership server-side on every object fetch:**

```python
svc = service_by_id(sid)
if svc is None or svc["owner"] != current_user()["id"]:
    abort(404)          # never leak "it exists but isn't yours"
```

**2. Same for tickets — the reference alone must not prove access:**

```python
ticket = ticket_by_id(tid)
if ticket is None or ticket["owner"] != current_user()["id"]:
    abort(404)
```

**3. Use unguessable, non-enumerable identifiers** (UUIDv4 / random 128-bit) for
object references instead of base64(sequential int) or `TKT-1001`.

**4. Never let customers paste live reset links into support.** If they do,
revoke the token the moment it's shared, and validate reset tokens against
**both** the token and a server-side binding (account, expiry, consumed-once).

**5. Security hardening:**
```python
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp
```

---

## ⚖️ Ethical guidelines

**✅ Acceptable:** running locally for learning; testing only against this app on
your own machine/network; writing professional bug reports; teaching in a
controlled environment.

**❌ Prohibited:** deploying to any public-facing server or cloud; testing against
real companies or any system you don't own; sharing this project in ways that
enable misuse.

---

## 🧾 Bug report template

```markdown
**Title:** IDOR in /service/<ref> allows viewing other customers' hosting services

**Vulnerability type:** Insecure Direct Object Reference (CWE-639)
**Severity:** High

**Description:**
The /service/<ref> endpoint loads a service by a base64 reference with no
ownership check, allowing any authenticated user to read any customer's service
config, server IP, SSH user, and deployment notes.

**Steps to reproduce:**
1. Log in as alex@cloudpeak.io / Cloudpeak#2026
2. Open one of your services, note the reference in the URL
3. Decode it (base64) → it is a sequential integer
4. Request /service/Mg==  (decodes to service 2)
5. Observe another customer's service details including credentials/notes

**Impact:** Full disclosure of customer infrastructure configuration and
server access details; enables further attacks against other customers.

**Remediation:** Enforce svc.owner == current_user().id on every request and
use unguessable object references.
```

---

*Built for bug-bounty practice. All users, companies, and infrastructure in this
project are fictional. CloudPeak is not a real hosting provider.*
