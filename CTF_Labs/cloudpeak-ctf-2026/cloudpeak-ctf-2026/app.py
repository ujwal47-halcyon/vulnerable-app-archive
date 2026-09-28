"""
CloudPeak (CTF Edition) — a deliberately vulnerable cloud-hosting SaaS for
bug-bounty / IDOR practice.

⚠️  FOR LOCAL, AUTHORIZED TRAINING ONLY. Every bug here is intentional.
    Never deploy this outside a machine/network you control.

This lab focuses on TWO different kinds of IDOR (Insecure Direct Object
Reference, CWE-639):

  CHALLENGE 1 — Horizontal object-level IDOR (CWE-639)
      Customer-owned resources (hosting services, invoices, and a JSON API
      surface) are fetched by an object reference that the client controls,
      with NO ownership check. References are base64-encoded sequential
      integers — decoding one proves they are enumerable.

  CHALLENGE 2 — Password-reset-token IDOR / account takeover (CWE-639 + CWE-640)
      Support tickets are also fetchable by reference with no ownership check.
      Client "Priya Sharma" pasted her (still-valid) password-reset link into
      a support ticket. Reading that ticket leaks the reset token, and the
      /reset/<token> flow trusts the bare token — so anyone who holds it can
      change the victim's password. Full account takeover.

How the CTF works: each challenge's flag is a visible string on the page you
reach by doing it right, and the exact response also carries an
`X-Cloudpeak-Flag` header (handy for curl/Burp practice). Track progress on
/challenges.

Run:
    pip install -r requirements.txt
    python app.py
Then browse to http://localhost:5000
"""

import base64
import json
import os
import time
import uuid

from flask import (Flask, redirect, render_template, request, session,
                   jsonify, make_response, url_for)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Stable dev secret so sessions survive restarts (matches the other labs).
app.secret_key = "cloudpeak-dev-only-secret-2026"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

USERS_FILE = os.path.join(DATA_DIR, "users.json")
SERVICES_FILE = os.path.join(DATA_DIR, "services.json")
INVOICES_FILE = os.path.join(DATA_DIR, "invoices.json")
TICKETS_FILE = os.path.join(DATA_DIR, "tickets.json")
TOKENS_FILE = os.path.join(DATA_DIR, "reset_tokens.json")

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

FLAG_IDOR_SERVICE = "CLOUDPEAK{0bj3ct_r3f3r3nc3_1s_n0t_4uth0r1z4t10n}"
FLAG_RESET_TAKEOVER = "CLOUDPEAK{l34k3d_r3s3t_t0k3n_3qu4ls_4cc0unt_t4k30v3r}"

CHALLENGES = [
    {
        "id": "idor_service",
        "title": "Horizontal IDOR — customer service details",
        "flag": FLAG_IDOR_SERVICE,
        "surface": "/service/<ref>, /api/service/<id>, /invoice/<id>",
        "summary": ("Customer resources are loaded by a client-controlled object "
                    "reference with no ownership check. References are base64 of "
                    "sequential integers."),
        "hint": ("Open one of your services from the dashboard. The URL holds a "
                 "short token that looks like a random code — decode it (it's "
                 "base64). It decodes to a sequential number. Try neighbouring "
                 "references: every customer's service is one guess away, and the "
                 "flag sits in someone's deployment notes."),
    },
    {
        "id": "reset_takeover",
        "title": "Password-reset-token IDOR → account takeover",
        "flag": FLAG_RESET_TAKEOVER,
        "surface": "/support/ticket/<ref> → /reset/<token>",
        "summary": ("Support tickets are readable by reference with no ownership "
                    "check. One ticket contains a client's disclosed password-reset "
                    "link; the reset endpoint trusts the bare token."),
        "hint": ("Tickets are numbered TKT-1001, TKT-1002, … and the portal only "
                 "lists your own. Walk the sequence. One customer pasted her "
                 "password-reset link into a ticket — the link is still valid. "
                 "Visit /reset/<token>, set a new password, and sign in as her. "
                 "Flag is on her dashboard."),
    },
]

# ---------------------------------------------------------------------------
# Tiny JSON persistence
# ---------------------------------------------------------------------------

def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return default
    return default


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


USERS = load_json(USERS_FILE, None)
SERVICES = load_json(SERVICES_FILE, None)
INVOICES = load_json(INVOICES_FILE, None)
TICKETS = load_json(TICKETS_FILE, None)
TOKENS = load_json(TOKENS_FILE, None)


def seed_data():
    """Seed realistic demo data on first launch. Never overwrites existing data."""
    global USERS, SERVICES, INVOICES, TICKETS, TOKENS
    now = int(time.time())

    if USERS is None:
        USERS = [
            {"id": 1,  "name": "Priya Sharma",  "email": "priya@cloudpeak.io",   "password": generate_password_hash("Priya@2026"),   "role": "user", "plan": "Pro",       "company": "Prysm Studio",      "created": "2024-03-12"},
            {"id": 2,  "name": "Daniel Okafor", "email": "daniel@cloudpeak.io",  "password": generate_password_hash("Daniel@2026"),  "role": "user", "plan": "Enterprise", "company": "Okafor Logistics", "created": "2023-11-02"},
            {"id": 3,  "name": "Mei Lin",       "email": "mei@cloudpeak.io",     "password": generate_password_hash("Mei@2026"),     "role": "user", "plan": "Business",   "company": "Lin Design Co.",     "created": "2025-01-20"},
            {"id": 4,  "name": "Alex Carter",   "email": "alex@cloudpeak.io",    "password": generate_password_hash("Cloudpeak#2026"), "role": "user", "plan": "Starter",   "company": "Carter Dev",        "created": "2026-05-30"},
            {"id": 5,  "name": "Rahul Mehta",   "email": "rahul@cloudpeak.io",   "password": generate_password_hash("Rahul@2026"),   "role": "user", "plan": "Starter",    "company": "Rahul Crafts",      "created": "2026-06-11"},
            {"id": 6,  "name": "Sofia Reyes",   "email": "sofia@cloudpeak.io",   "password": generate_password_hash("Sofia@2026"),   "role": "user", "plan": "Business",   "company": "Sofia Dental",      "created": "2026-02-08"},
            {"id": 99, "name": "Platform Admin", "email": "admin@cloudpeak.io",  "password": generate_password_hash("admin123"),     "role": "admin", "plan": "Internal",  "company": "CloudPeak",         "created": "2022-01-01"},
        ]
        save_json(USERS_FILE, USERS)

    if SERVICES is None:
        SERVICES = [
            {"id": 1, "owner": 1, "name": "Prysm Studio — Production",   "domain": "prysmstudio.com",           "plan": "Pro",       "region": "ap-south-1", "ip": "103.21.58.14",  "ssh_user": "prismprod",  "vcore": 4, "ram": 8,  "disk": 160, "status": "active",    "created": "2024-03-14", "notes": "Canonical record for prysmstudio.com. Snapshots restored from the ap-south-1 backup bucket.", "next_renewal": "2026-09-12"},
            {"id": 2, "owner": 2, "name": "Okafor Logistics — Fleet Portal", "domain": "okaforlogistics.com",    "plan": "Enterprise", "region": "eu-west-1",  "ip": "54.194.88.201", "ssh_user": "okafor-ops", "vcore": 8, "ram": 32, "disk": 512, "status": "active",    "created": "2023-11-05", "notes": f"{FLAG_IDOR_SERVICE} — move to secrets vault before go-live. Legacy SFTP user okafor-ops still maps to /srv/okafor.", "next_renewal": "2026-11-05"},
            {"id": 3, "owner": 3, "name": "Lin Design — Portfolio",       "domain": "meilindesign.co",           "plan": "Business",  "region": "us-east-1",  "ip": "3.211.77.140",  "ssh_user": "lin-web",    "vcore": 4, "ram": 16, "disk": 256, "status": "active",    "created": "2025-01-22", "notes": "Static site served by nginx + Let's Encrypt.", "next_renewal": "2027-01-22"},
            {"id": 4, "owner": 4, "name": "Carter Dev — Staging",          "domain": "staging.carterdev.io",      "plan": "Starter",   "region": "us-east-1",  "ip": "44.203.11.92",  "ssh_user": "carterdev",  "vcore": 2, "ram": 4,  "disk": 80,  "status": "active",    "created": "2026-06-01", "notes": "Staging only — no production data.", "next_renewal": "2026-12-01"},
            {"id": 5, "owner": 5, "name": "Rahul Crafts — Store",          "domain": "rahulcrafts.in",            "plan": "Starter",   "region": "ap-south-1", "ip": "103.21.58.33",  "ssh_user": "rahul-web",  "vcore": 2, "ram": 4,  "disk": 80,  "status": "suspended", "created": "2026-06-15", "notes": "Account flagged for non-payment; suspension requested by support.", "next_renewal": "2026-09-15"},
            {"id": 6, "owner": 6, "name": "Sofia Dental — Booking",        "domain": "sofiadental.com",           "plan": "Business",  "region": "eu-west-1",  "ip": "52.18.102.77",  "ssh_user": "sofia-app",  "vcore": 4, "ram": 16, "disk": 200, "status": "active",    "created": "2026-02-10", "notes": "Online booking + patient forms.", "next_renewal": "2027-02-10"},
            {"id": 7, "owner": 99, "name": "CloudPeak — Internal Admin Console", "domain": "admin-console.cloudpeak.internal", "plan": "Internal", "region": "ap-south-1", "ip": "10.0.4.21", "ssh_user": "cp-infra", "vcore": 16, "ram": 64, "disk": 1024, "status": "active", "created": "2022-01-05", "notes": "Internal only — reachable over VPN. Do not expose to the public internet.", "next_renewal": "-"},
        ]
        save_json(SERVICES_FILE, SERVICES)

    if INVOICES is None:
        INVOICES = [
            {"id": 1, "owner": 1, "ref": "INV-2026-0801", "service": 1, "amount": 299.00,  "status": "paid",    "issued": "2026-08-01", "due": "2026-08-15"},
            {"id": 2, "owner": 2, "ref": "INV-2026-0802", "service": 2, "amount": 1899.00, "status": "paid",    "issued": "2026-08-01", "due": "2026-08-16"},
            {"id": 3, "owner": 3, "ref": "INV-2026-0803", "service": 3, "amount": 899.00,  "status": "overdue", "issued": "2026-07-01", "due": "2026-07-20"},
            {"id": 4, "owner": 4, "ref": "INV-2026-0804", "service": 4, "amount": 49.00,   "status": "paid",    "issued": "2026-08-02", "due": "2026-08-17"},
            {"id": 5, "owner": 5, "ref": "INV-2026-0705", "service": 5, "amount": 49.00,   "status": "overdue", "issued": "2026-07-01", "due": "2026-07-20"},
            {"id": 6, "owner": 6, "ref": "INV-2026-0806", "service": 6, "amount": 899.00,  "status": "paid",    "issued": "2026-08-01", "due": "2026-08-15"},
        ]
        save_json(INVOICES_FILE, INVOICES)

    if TICKETS is None:
        RESET_TOKEN = "3f9c1a2e-8b4d-4c5f-9e21-a7b3d5c8f2e1"
        TICKETS = [
            {"id": 1, "ref": "TKT-1001", "owner": 4, "subject": "Requesting staging environment access", "message": "Hi team, I need SSH access to the staging box (staging.carterdev.io) to test our new checkout flow. Please add my deploy key.", "status": "resolved",    "priority": "low",    "created": "2026-07-14", "attachment": None},
            {"id": 2, "ref": "TKT-1002", "owner": 6, "subject": "Invoice INV-2026-0806 not emailed",       "message": "I didn't receive the invoice PDF in my inbox. Can you resend it to billing@sofiadental.com?", "status": "open", "priority": "normal", "created": "2026-08-02", "attachment": None},
            {"id": 3, "ref": "TKT-1003", "owner": 2, "subject": "Slow response from Fleet Portal",          "message": "Load times spiked on the fleet dashboard since the last deploy. Can ops check CPU on the eu-west-1 box?", "status": "in_progress", "priority": "high", "created": "2026-08-05", "attachment": None},
            {"id": 4, "ref": "TKT-1004", "owner": 3, "subject": "Certificate renewal stuck",                "message": "Let's Encrypt renewal failed twice on meilindesign.co. The http-01 challenge keeps timing out.", "status": "open", "priority": "normal", "created": "2026-08-06", "attachment": None},
            {"id": 5, "ref": "TKT-1005", "owner": 1, "subject": "Password reset link not working",          "message": "Hi, I'm locked out of my account. I requested a password reset but the link from the email keeps saying 'invalid or expired'. Here is the exact link I received so you can check what's wrong:\n\nhttps://localhost:5000/reset/" + RESET_TOKEN + "\n\nIt was emailed to priya@cloudpeak.io. Please advise.", "status": "open", "priority": "high", "created": "2026-08-09", "attachment": "password-reset-email.png"},
            {"id": 6, "ref": "TKT-1006", "owner": 5, "subject": "Why is my service suspended?",             "message": "I got a notice that rahulcrafts.in is suspended for non-payment but I have auto-pay enabled. Can you check?", "status": "open", "priority": "normal", "created": "2026-08-09", "attachment": None},
            {"id": 7, "ref": "TKT-1007", "owner": 1, "subject": "Change billing email",                     "message": "Please change the billing contact on my account to accounts@prysmstudio.com.", "status": "resolved", "priority": "low", "created": "2026-07-22", "attachment": None},
        ]
        save_json(TICKETS_FILE, TICKETS)

        # Priya's reset token is still VALID (issued today, expires in 30 days).
        # This is exactly the situation the real-world bug describes: a client
        # disclosed her password-reset link to support, and nobody revoked it.
        TOKENS = {
            RESET_TOKEN: {
                "email": "priya@cloudpeak.io",
                "created": "2026-08-09",
                "expires": now + 30 * 86400,
                "source": "support-ticket-disclosure",
            }
        }
        save_json(TOKENS_FILE, TOKENS)


seed_data()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_user(user_id=None, email=None):
    for u in USERS:
        if user_id is not None and u["id"] == user_id:
            return u
        if email is not None and u["email"].lower() == email.lower():
            return u
    return None


def current_user():
    uid = session.get("uid")
    if uid is None:
        return None
    return find_user(user_id=uid)


@app.context_processor
def inject_user():
    """Expose the logged-in user to every template (used by the navbar)."""
    return {"user": current_user()}


def login_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login", next=request.path))
        if user["role"] != "admin":
            return render_template("403.html", path=request.path), 403
        return fn(*args, **kwargs)
    return wrapper


def encode_ref(sid):
    """base64 of the sequential integer, no padding (URL-safe-ish)."""
    return base64.b64encode(str(sid).encode()).decode().rstrip("=")


def decode_ref(ref):
    """Reverse of encode_ref. Returns an int, or None on garbage."""
    if not ref:
        return None
    try:
        padded = ref + "=" * (-len(ref) % 4)
        return int(base64.b64decode(padded).decode())
    except Exception:
        return None


def parse_ticket_ref(ref):
    """TKT-1005 -> 5. Returns an int, or None."""
    if not ref:
        return None
    r = ref.strip().upper()
    if r.startswith("TKT-"):
        r = r[4:]
    if r.isdigit():
        return int(r) - 1000
    return None


def service_by_id(sid):
    for s in SERVICES:
        if s["id"] == sid:
            return s
    return None


def ticket_by_id(tid):
    for t in TICKETS:
        if t["id"] == tid:
            return t
    return None


def invoice_by_id(iid):
    for inv in INVOICES:
        if inv["id"] == iid:
            return inv
    return None


def token_lookup(token):
    rec = TOKENS.get(token)
    if not rec:
        return None
    if int(rec.get("expires", 0)) < time.time():
        return None
    return rec


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/pricing")
def pricing():
    return render_template("pricing.html")


@app.route("/features")
def features():
    return render_template("features.html")


@app.route("/challenges")
def challenges():
    return render_template("challenges.html", challenges=CHALLENGES)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        company = request.form.get("company", "").strip()

        if not name or not email or not password:
            error = "All fields are required."
        elif "@" not in email:
            error = "Enter a valid email address."
        elif find_user(email=email):
            error = "An account with that email already exists."
        else:
            new_id = max((u["id"] for u in USERS), default=0) + 1
            USERS.append({
                "id": new_id,
                "name": name,
                "email": email,
                "password": generate_password_hash(password),
                "role": "user",
                "plan": "Starter",
                "company": company or "—",
                "created": time.strftime("%Y-%m-%d"),
            })
            save_json(USERS_FILE, USERS)
            session["uid"] = new_id
            return redirect("/dashboard")

    return render_template("signup.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = find_user(email=email)
        if user and check_password_hash(user["password"], password):
            session["uid"] = user["id"]
            nxt = request.args.get("next") or "/dashboard"
            return redirect(nxt)
        error = "Invalid email or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------------------------------------------------------------------
# Password reset — Challenge 2's vulnerable surface
# ---------------------------------------------------------------------------

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    sent = False
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = find_user(email=email)
        if not user:
            # No user enumeration: same generic message either way.
            sent = True
        else:
            token = str(uuid.uuid4())
            TOKENS[token] = {
                "email": user["email"],
                "created": time.strftime("%Y-%m-%d"),
                "expires": int(time.time()) + 24 * 3600,
                "source": "forgot-form",
            }
            save_json(TOKENS_FILE, TOKENS)
            # No SMTP in the lab — this is the "outgoing email" dev log.
            print("\n[CloudPeak dev-mail] To:", user["email"])
            print("[CloudPeak dev-mail] Subject: Reset your CloudPeak password")
            print(f"[CloudPeak dev-mail] Link: {request.host_url.rstrip('/')}/reset/{token}\n")
            sent = True
    return render_template("forgot.html", sent=sent, error=error)


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    rec = token_lookup(token)
    error = None
    done = False
    takeover = False
    flag = None

    if rec is None:
        return render_template("reset.html", invalid=True, done=False)

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            user = find_user(email=rec["email"])
            if user is None:
                error = "Account no longer exists."
            else:
                user["password"] = generate_password_hash(password)
                save_json(USERS_FILE, USERS)
                del TOKENS[token]
                save_json(TOKENS_FILE, TOKENS)
                done = True
                me = current_user()
                # VULNERABILITY (Challenge 2): the endpoint trusts the bare
                # token. If the token belongs to someone other than the person
                # currently making the request, that's an account takeover.
                takeover = me is None or me["email"] != rec["email"]
                if takeover:
                    flag = FLAG_RESET_TAKEOVER

    resp = make_response(render_template(
        "reset.html", invalid=False, done=done, error=error, takeover=takeover,
        flag=flag, email=rec.get("email"),
    ))
    if flag:
        resp.headers["X-Cloudpeak-Flag"] = flag
    return resp


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()

    def enrich_service(s):
        return {**s, "ref": encode_ref(s["id"])}

    my_services = [enrich_service(s) for s in SERVICES if s["owner"] == user["id"]]

    def enrich_invoice(i):
        svc = service_by_id(i["service"])
        return {**i, "service_name": svc["name"] if svc else "—"}

    my_invoices = [enrich_invoice(i) for i in INVOICES if i["owner"] == user["id"]]
    my_tickets = [t for t in TICKETS if t["owner"] == user["id"]]

    resp = make_response(render_template(
        "dashboard.html", user=user,
        services=my_services, invoices=my_invoices, tickets=my_tickets,
    ))
    # Challenge 2 flag also appears on the victim's own dashboard after you
    # take the account over — you "are" Priya by then.
    if user["email"] == "priya@cloudpeak.io":
        resp.headers["X-Cloudpeak-Flag"] = FLAG_RESET_TAKEOVER
    return resp


# ---------------------------------------------------------------------------
# CHALLENGE 1 — Horizontal object-level IDOR (CWE-639)
# ---------------------------------------------------------------------------

@app.route("/service/<ref>")
@login_required
def service_detail(ref):
    sid = decode_ref(ref)
    svc = service_by_id(sid) if sid is not None else None
    if svc is None:
        return render_template("404.html", path=request.path), 404

    owner = find_user(user_id=svc["owner"])
    me = current_user()

    # VULNERABILITY: no `svc["owner"] == me["id"]` check. Any logged-in user
    # can view any customer's service by guessing/enumerating the reference.
    resp = make_response(render_template(
        "service.html", service=svc, owner=owner, ref=ref,
        is_own=owner["id"] == me["id"], flag=FLAG_IDOR_SERVICE if owner["id"] != me["id"] else None,
    ))
    if owner["id"] != me["id"]:
        resp.headers["X-Cloudpeak-Flag"] = FLAG_IDOR_SERVICE
    return resp


@app.route("/api/service/<int:sid>")
@login_required
def api_service(sid):
    svc = service_by_id(sid)
    if svc is None:
        return jsonify({"error": "service not found"}), 404

    # VULNERABILITY: same missing ownership check on the API surface.
    me = current_user()
    payload = {k: v for k, v in svc.items()}
    payload["owner_email"] = find_user(user_id=svc["owner"])["email"]
    resp = make_response(jsonify(payload))
    if svc["owner"] != me["id"]:
        resp.headers["X-Cloudpeak-Flag"] = FLAG_IDOR_SERVICE
    return resp


@app.route("/invoice/<int:iid>")
@login_required
def invoice_detail(iid):
    inv = invoice_by_id(iid)
    if inv is None:
        return render_template("404.html", path=request.path), 404

    owner = find_user(user_id=inv["owner"])
    me = current_user()

    # VULNERABILITY: no ownership check — enumerate invoice ids for billing info.
    resp = make_response(render_template(
        "invoice.html", invoice=inv, owner=owner, is_own=owner["id"] == me["id"],
    ))
    return resp


# ---------------------------------------------------------------------------
# Support portal — Challenge 2's entry point
# ---------------------------------------------------------------------------

@app.route("/support", methods=["GET", "POST"])
@login_required
def support():
    user = current_user()
    error = None
    created = None

    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        priority = request.form.get("priority", "normal")
        if not subject or not message:
            error = "Subject and message are required."
        else:
            new_id = max((t["id"] for t in TICKETS), default=0) + 1
            TICKETS.append({
                "id": new_id,
                "ref": f"TKT-{1000 + new_id}",
                "owner": user["id"],
                "subject": subject,
                "message": message,
                "status": "open",
                "priority": priority,
                "created": time.strftime("%Y-%m-%d"),
                "attachment": None,
            })
            save_json(TICKETS_FILE, TICKETS)
            created = f"TKT-{1000 + new_id}"

    my_tickets = sorted(
        (t for t in TICKETS if t["owner"] == user["id"]),
        key=lambda t: t["id"], reverse=True,
    )
    return render_template("support.html", tickets=my_tickets, error=error, created=created)


@app.route("/support/ticket/<ref>")
@login_required
def ticket_detail(ref):
    tid = parse_ticket_ref(ref)
    ticket = ticket_by_id(tid) if tid is not None else None
    if ticket is None:
        return render_template("404.html", path=request.path), 404

    owner = find_user(user_id=ticket["owner"])

    # VULNERABILITY (Challenge 2): no ownership check. Read anyone's ticket —
    # including TKT-1005, which contains a disclosed password-reset link.
    resp = make_response(render_template("ticket.html", ticket=ticket, owner=owner))
    return resp


# ---------------------------------------------------------------------------
# Admin (trainer tooling — legitimately role-gated, not an IDOR target)
# ---------------------------------------------------------------------------

@app.route("/admin")
@admin_required
def admin_panel():
    return render_template("admin.html", users=USERS, services=SERVICES, tickets=TICKETS)


@app.route("/admin/users/<int:uid>/reset-password", methods=["POST"])
@admin_required
def admin_reset_password(uid):
    user = find_user(user_id=uid)
    if user:
        new_pw = request.form.get("new_password", "")
        if len(new_pw) >= 6:
            user["password"] = generate_password_hash(new_pw)
            save_json(USERS_FILE, USERS)
            print(f"[CloudPeak admin] Password for {user['email']} set to '{new_pw}'")
    return redirect("/admin")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", path=request.path), 404


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 64)
    print("  CloudPeak — IDOR Training Lab (CTF Edition)")
    print("  Deliberately vulnerable — LOCAL USE ONLY")
    print("=" * 64)
    print("  URL:      http://localhost:5000")
    print("  Admin:    admin@cloudpeak.io / admin123")
    print("  Demo:     alex@cloudpeak.io / Cloudpeak#2026")
    print("  Port:     5000  (edit the app.run line if busy)")
    print("  Data:     ./data/*.json  (auto-created, persists)")
    print("  Flags:    see /challenges — 2 challenges, both IDOR (CWE-639)")
    print("=" * 64)
    app.run(debug=True, host="0.0.0.0", port=5000)
