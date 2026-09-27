"""
================================================================================
 MediLink Health — 2026 CTF Lab  (deliberately vulnerable telehealth portal)
================================================================================
 A realistic telehealth/patient-portal application used as a capture-the-flag
 training target. Intermediate difficulty. All 10 vulnerabilities are marked
 with a "# VULNERABILITY" comment.

 ⚠️  EDUCATIONAL USE ONLY — run locally on your own machine. NEVER deploy.
================================================================================
"""

from flask import (Flask, render_template, request, redirect, url_for, session,
                   jsonify, make_response, g)
import json
import os
import re
import hashlib
import random
import secrets
import time
import uuid
from datetime import datetime

# ----------------------------------------------------------------------------
# Paths + persistent storage (everything survives restarts)
# ----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

USERS_FILE        = os.path.join(DATA_DIR, 'users.json')
RECORDS_FILE      = os.path.join(DATA_DIR, 'records.json')
APPOINTMENTS_FILE = os.path.join(DATA_DIR, 'appointments.json')
MESSAGES_FILE     = os.path.join(DATA_DIR, 'messages.json')
OTPS_FILE         = os.path.join(DATA_DIR, 'otps.json')
RESET_FILE        = os.path.join(DATA_DIR, 'reset_tokens.json')
PLAYERS_FILE      = os.path.join(DATA_DIR, 'players.json')
DEADLINE_FILE     = os.path.join(DATA_DIR, 'deadline.json')
SECRET_FILE       = os.path.join(DATA_DIR, 'secret_key.txt')

app = Flask(__name__)


def _load_secret():
    """Persisted secret key — sessions stay valid across restarts."""
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, 'w') as f:
            f.write(secrets.token_hex(32))
    with open(SECRET_FILE) as f:
        return f.read().strip()


app.secret_key = _load_secret()


# ----------------------------------------------------------------------------
# Data helpers
# ----------------------------------------------------------------------------
def load_data(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return [] if path.endswith('.json') else {}


def save_data(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ----------------------------------------------------------------------------
# Seeded data — created once on first run, then persisted forever
# ----------------------------------------------------------------------------
def seed_if_missing():
    if not os.path.exists(USERS_FILE):
        save_data(USERS_FILE, [
            {"id": 101, "name": "Jordan Lee", "email": "jordan@medilink.health",
             "password": "Jordan#2026", "role": "patient",
             "phone": "(555) 010-2201", "dob": "1989-04-12", "allergies": ["Penicillin"]},
            {"id": 102, "name": "Amy Chen", "email": "amy@medilink.health",
             "password": "Amy#2026", "role": "patient",
             "phone": "(555) 010-2254", "dob": "1992-11-03", "allergies": ["None on file"]},
            {"id": 103, "name": "Raj Patel", "email": "raj@medilink.health",
             "password": "Raj#2026", "role": "patient",
             "phone": "(555) 010-2330", "dob": "1978-02-27", "allergies": ["Sulfa drugs"]},
            {"id": 201, "name": "Dr. Alex Rivera", "email": "dr.alex@medilink.health",
             "password": "M3d1l1nk#2026", "role": "staff", "title": "Cardiologist",
             "phone": "(555) 010-3000", "dob": "1975-06-19", "allergies": [], "otp_enabled": True},
        ])
    if not os.path.exists(RECORDS_FILE):
        save_data(RECORDS_FILE, [
            {"id": 1, "patient_id": 101, "provider": "Dr. Alex Rivera",
             "diagnosis": "Seasonal allergies", "medications": ["Loratadine 10mg"],
             "notes": "Patient stable. Recheck in autumn.", "last_visit": "2026-07-20"},
            {"id": 2, "patient_id": 102, "provider": "Dr. Alex Rivera",
             "diagnosis": "Hypertension (Stage 1)", "medications": ["Amlodipine 5mg"],
             "notes": "BP trending down. Continue meds.", "last_visit": "2026-07-28"},
            {"id": 3, "patient_id": 103, "provider": "Dr. Alex Rivera",
             "diagnosis": "Type 2 diabetes", "medications": ["Metformin 500mg"],
             "notes": "A1C improving. Follow up labs ordered.", "last_visit": "2026-08-01"},
            {"id": 4, "patient_id": 101, "provider": "Dr. Alex Rivera",
             "diagnosis": "Routine physical", "medications": [],
             "notes": "All clear.", "last_visit": "2026-08-03"},
        ])
    if not os.path.exists(APPOINTMENTS_FILE):
        save_data(APPOINTMENTS_FILE, [
            {"id": 1, "patient_id": 101, "patient_name": "Jordan Lee",
             "doctor": "Dr. Alex Rivera", "type": "Cardiology consult",
             "date": "2026-08-14", "time": "10:00", "status": "confirmed"},
            {"id": 2, "patient_id": 102, "patient_name": "Amy Chen",
             "doctor": "Dr. Alex Rivera", "type": "Hypertension follow-up",
             "date": "2026-08-12", "time": "09:30", "status": "confirmed"},
            {"id": 3, "patient_id": 103, "patient_name": "Raj Patel",
             "doctor": "Dr. Alex Rivera", "type": "Diabetes review",
             "date": "2026-08-13", "time": "14:00", "status": "confirmed"},
        ])
    if not os.path.exists(MESSAGES_FILE):
        save_data(MESSAGES_FILE, [
            {"id": 1, "from_email": "amy@medilink.health", "from_name": "Amy Chen",
             "subject": "Refill request", "message": "Hi Dr. Rivera, could you refill my prescription? Thanks!",
             "ts": "2026-08-04 09:12"},
            {"id": 2, "from_email": "raj@medilink.health", "from_name": "Raj Patel",
             "subject": "Lab results", "message": "Can you review my latest labs before the appointment?",
             "ts": "2026-08-04 16:40"},
        ])
    if not os.path.exists(OTPS_FILE):
        save_data(OTPS_FILE, {})
    if not os.path.exists(RESET_FILE):
        save_data(RESET_FILE, {})
    if not os.path.exists(PLAYERS_FILE):
        save_data(PLAYERS_FILE, {})
    if not os.path.exists(DEADLINE_FILE):
        save_data(DEADLINE_FILE, {"deadline": "2026-08-19T23:59:59",
                                  "label": "Finish by August 19, 2026"})


seed_if_missing()


# ----------------------------------------------------------------------------
# CTF meta — flags + challenge catalog
# ----------------------------------------------------------------------------
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

CHALLENGES = [
    {"id": "warmup_stored_xss", "name": "Portal messages are a hot mess",
     "category": "XSS · Stored", "difficulty": "Easy",
     "hint": "Anything you message the care team gets stored and shown back raw."},
    {"id": "reflected_xss", "name": "Search & destroy",
     "category": "XSS · Reflected", "difficulty": "Easy",
     "hint": "The search page echoes your query right back into the page markup."},
    {"id": "idor_records", "name": "Whose record is this?",
     "category": "Access Control · IDOR", "difficulty": "Easy→Int",
     "hint": "Record IDs are sequential. The detail page may not check who owns them."},
    {"id": "idor_appointments", "name": "Cancel someone else's Tuesday",
     "category": "Access Control · IDOR (write)", "difficulty": "Intermediate",
     "hint": "Write paths need ownership checks too."},
    {"id": "bac_staff", "name": "The staff room has no key",
     "category": "Access Control · Function-level", "difficulty": "Intermediate",
     "hint": "A link being hidden is not the same as an endpoint being protected."},
    {"id": "mass_assignment", "name": "Role your own",
     "category": "Access Control · API", "difficulty": "Intermediate",
     "hint": "The profile API copies whatever fields you send it."},
    {"id": "nrl_login", "name": "Guess who",
     "category": "Auth · No rate limit", "difficulty": "Intermediate",
     "hint": "The memo explains the staff password format. No lockout = unlimited tries."},
    {"id": "nrl_otp", "name": "Four digits too many",
     "category": "Auth · No rate limit", "difficulty": "Intermediate",
     "hint": "The second factor is a 4-digit code with no attempt limit."},
    {"id": "auth_reset", "name": "Predictable recovery",
     "category": "Auth · Bypass", "difficulty": "Intermediate",
     "hint": "Password-reset tokens are generated from things an attacker can know."},
    {"id": "dom_xss", "name": "Hash & splash",
     "category": "XSS · DOM", "difficulty": "Intermediate",
     "hint": "A client-side viewer trusts location.hash and writes it to the DOM."},
]

# Regex used to detect a live XSS signature when a sink renders (a stand-in for
# 'the payload actually executed'). The beacon is the other, explicit path.
XSS_SIG = re.compile(r"<\s*script|<\s*(?:img|svg|iframe|object|video)[^>]*\s|\bon[a-z]+\s*=|\bjavascript\s*:", re.IGNORECASE)


# ----------------------------------------------------------------------------
# Player identity + flag bookkeeping (persisted to players.json)
# ----------------------------------------------------------------------------
@app.before_request
def _load_pid():
    g.pid = request.cookies.get('player_id') or str(uuid.uuid4())


@app.after_request
def _set_pid(resp):
    if not request.cookies.get('player_id'):
        resp.set_cookie('player_id', g.pid, max_age=365 * 24 * 3600)
    return resp


def player_id():
    return g.pid


def register_solve(challenge_id):
    if challenge_id not in FLAGS:
        return
    players = load_data(PLAYERS_FILE)
    players.setdefault(g.pid, {})
    if challenge_id not in players[g.pid]:
        players[g.pid][challenge_id] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        save_data(PLAYERS_FILE, players)


def issue_flag(challenge_id, resp):
    """Attach the flag to a response AND register it as solved for this player."""
    if challenge_id in FLAGS:
        register_solve(challenge_id)
        resp.headers['X-Medilink-Flag'] = FLAGS[challenge_id]
    return resp


# ----------------------------------------------------------------------------
# Auth / role helpers  (deliberately inconsistent role handling = the point)
# ----------------------------------------------------------------------------
def current_user():
    email = session.get('email')
    if not email:
        return None
    for u in load_data(USERS_FILE):
        if u.get('email') == email:
            return u
    return None


def is_staff():
    u = current_user()
    return bool(u and u.get('role') == 'staff')


def need_login():
    return redirect(url_for('login'))


def mask_email(email):
    local, _, domain = email.partition('@')
    return f"{local[:2]}***@{domain}" if local else email


# Reset-token derivation — intentionally predictable (CWE-640).
def reset_token_for(user_id, epoch_minute):
    raw = f"{user_id}|{epoch_minute}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def resolve_reset_token(token):
    """Which user does this token belong to? Derived over the last 6 minute buckets."""
    users = load_data(USERS_FILE)
    now_min = int(time.time()) // 60
    for u in users:
        for back in range(6):
            cand = reset_token_for(u['id'], now_min - back)
            if secrets.compare_digest(cand, token):
                return u
    return None


# ----------------------------------------------------------------------------
# Recon surface (robots.txt + a leaked memo + a public staff directory)
# ----------------------------------------------------------------------------
@app.route('/robots.txt')
def robots():
    body = (
        "User-agent: *\n"
        "Disallow: /staff/\n"
        "Disallow: /api/\n"
        "Disallow: /company-memo.txt\n"
        "Disallow: /preview\n"
        "Disallow: /reset\n"
    )
    resp = make_response(body, 200)
    resp.headers['Content-Type'] = 'text/plain'
    return resp


@app.route('/company-memo.txt')
def company_memo():
    body = (
        "MEDILINK HEALTH — INTERNAL MEMO (HR)\n"
        "Subject: Quarterly staff credential rotation — Q3 2026\n"
        "\n"
        "All staff logins were rotated at the start of Q3. The rotation format is the\n"
        "org standard introduced in 2023:\n"
        "\n"
        "    <leetspeak brand> + <symbol> + <current year>\n"
        "\n"
        "Brand here means 'Medilink'. As a format example only (NOT the real value), a\n"
        "hypothetical brand like 'Acme' would rotate to: 4CM3@2026\n"
        "\n"
        "Dr. Alex Rivera (dr.alex@medilink.health) confirmed completion of his rotation.\n"
        "Staff are reminded that the login endpoint does not enforce a lockout policy.\n"
        "\n"
        "(This memo was accidentally uploaded to the public CDN bucket. Please ignore.)\n"
    )
    resp = make_response(body, 200)
    resp.headers['Content-Type'] = 'text/plain'
    return resp


@app.route('/api/directory')
def api_directory():
    # VULNERABILITY: public staff directory leaks internal IDs + emails (recon).
    staff = [u for u in load_data(USERS_FILE) if u.get('role') == 'staff']
    return jsonify([{"id": u['id'], "name": u['name'], "email": u['email'],
                     "title": u.get('title')} for u in staff])


# ----------------------------------------------------------------------------
# Public pages
# ----------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


# ----------------------------------------------------------------------------
# Login — VULNERABILITY #7: no rate limiting / lockout
# ----------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = next((u for u in load_data(USERS_FILE) if u.get('email') == email), None)

        # VULNERABILITY: unlimited attempts, no lockout, no CAPTCHA -> brute force.
        # Passwords also stored in plaintext (another real-world sin).
        if user and user.get('password') == password:
            if user.get('role') == 'staff' and not session.get('otp_verified'):
                # Issue a fresh 4-digit OTP, stored server-side.
                otps = load_data(OTPS_FILE)
                otps[email] = str(random.randint(0, 9999)).zfill(4)
                save_data(OTPS_FILE, otps)
                session['pending_email'] = email
                resp = redirect(url_for('verify_otp'))
                # flag: staff password found by guessing with no limit
                issue_flag('nrl_login', resp)
                return resp
            session['email'] = email
            resp = redirect(url_for('dashboard'))
            return resp

        return render_template('login.html', error='Invalid credentials.', email=email)

    return render_template('login.html')


# ----------------------------------------------------------------------------
# OTP verification — VULNERABILITY #8: no rate limit on the second factor
# ----------------------------------------------------------------------------
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    pending = session.get('pending_email')
    if not pending:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('otp', '')
        otps = load_data(OTPS_FILE)
        # VULNERABILITY: 4-digit code, unlimited guesses, no cooldown -> brute force.
        if otps.get(pending) == code:
            session['email'] = pending
            session['otp_verified'] = True
            session.pop('pending_email', None)
            resp = redirect(url_for('dashboard'))
            issue_flag('nrl_otp', resp)
            return resp
        return render_template('verify_otp.html', error='Invalid code.',
                               masked=mask_email(pending))

    return render_template('verify_otp.html', masked=mask_email(pending))


# ----------------------------------------------------------------------------
# Password reset — VULNERABILITY #9: predictable reset token
# ----------------------------------------------------------------------------
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = next((u for u in load_data(USERS_FILE) if u.get('email') == email), None)
        if user:
            # VULNERABILITY: token = md5(user_id | epoch_minute), derivable by anyone.
            minute = int(time.time()) // 60
            token = reset_token_for(user['id'], minute)
            resets = load_data(RESET_FILE)
            resets[email] = token
            save_data(RESET_FILE, resets)
            # In a real app this link is emailed. Here the derivation hint lives in
            # the page source (recon) instead.
            return render_template('forgot.html', sent=True, email=email,
                                   user_id=user['id'])
        return render_template('forgot.html', error='No account with that email.')

    return render_template('forgot.html')


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    token = request.args.get('token', '')

    if request.method == 'POST':
        token = request.form.get('token', '')
        new_password = request.form.get('password', '')
        user = resolve_reset_token(token)
        if user and new_password:
            users = load_data(USERS_FILE)
            for i, u in enumerate(users):
                if u['id'] == user['id']:
                    users[i]['password'] = new_password   # account takeover
                    break
            save_data(USERS_FILE, users)
            resets = load_data(RESET_FILE)
            resets.pop(user['email'], None)
            save_data(RESET_FILE, resets)
            # A completed reset is treated as strong auth -> no OTP re-challenge.
            session['email'] = user['email']
            session['otp_verified'] = True
            resp = redirect(url_for('dashboard'))
            issue_flag('auth_reset', resp)
            return resp
        return render_template('reset.html', invalid=True)

    user = resolve_reset_token(token)
    if not user:
        return render_template('reset.html', invalid=True)
    return render_template('reset.html', email=user['email'], token=token)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ----------------------------------------------------------------------------
# Patient portal — requires login
# ----------------------------------------------------------------------------
@app.route('/dashboard')
def dashboard():
    if not session.get('email'):
        return need_login()
    u = current_user()
    records = [r for r in load_data(RECORDS_FILE) if r.get('patient_id') == u['id']]
    appts = [a for a in load_data(APPOINTMENTS_FILE) if a.get('patient_id') == u['id']]
    msgs = [m for m in load_data(MESSAGES_FILE) if m.get('from_email') == u['email']]
    return render_template('dashboard.html', user=u, records=records,
                           appointments=appts, messages=msgs)


# ----------------------------------------------------------------------------
# Records — VULNERABILITY #3: IDOR (no ownership check on the detail view)
# ----------------------------------------------------------------------------
@app.route('/records')
def records():
    if not session.get('email'):
        return need_login()
    u = current_user()
    mine = [r for r in load_data(RECORDS_FILE) if r.get('patient_id') == u['id']]
    return render_template('records.html', records=mine)


@app.route('/records/<int:rid>')
def record_detail(rid):
    if not session.get('email'):
        return need_login()
    rec = next((r for r in load_data(RECORDS_FILE) if r.get('id') == rid), None)
    if not rec:
        return render_template('notfound.html', thing='record'), 404
    u = current_user()
    flag = None
    # VULNERABILITY: fetch by ID, no check that this record belongs to the caller.
    if rec.get('patient_id') != u['id']:
        flag = 'idor_records'
    resp = make_response(render_template('record_detail.html', record=rec,
                                         is_owner=rec.get('patient_id') == u['id'],
                                         captured_flag=FLAGS[flag] if flag else None))
    if flag:
        issue_flag(flag, resp)
    return resp


# ----------------------------------------------------------------------------
# Appointments — VULNERABILITY #4: IDOR on the write path (cancel/reschedule)
# ----------------------------------------------------------------------------
@app.route('/appointments')
def appointments():
    if not session.get('email'):
        return need_login()
    u = current_user()
    mine = [a for a in load_data(APPOINTMENTS_FILE) if a.get('patient_id') == u['id']]
    return render_template('appointments.html', appointments=mine)


@app.route('/appointments/<int:aid>/cancel', methods=['POST'])
def cancel_appointment(aid):
    if not session.get('email'):
        return need_login()
    appts = load_data(APPOINTMENTS_FILE)
    apt = next((a for a in appts if a.get('id') == aid), None)
    if not apt:
        return render_template('notfound.html', thing='appointment'), 404
    u = current_user()
    flag = None
    # VULNERABILITY: no ownership check before mutating someone else's appointment.
    if apt.get('patient_id') != u['id']:
        flag = 'idor_appointments'
    apt['status'] = 'cancelled'
    apt['cancelled_at'] = datetime.now().isoformat()
    save_data(APPOINTMENTS_FILE, appts)
    resp = redirect(url_for('appointments'))
    if flag:
        issue_flag(flag, resp)
    return resp


# ----------------------------------------------------------------------------
# Messaging — VULNERABILITY #1: stored XSS (unsanitized input, |safe sink)
# ----------------------------------------------------------------------------
@app.route('/messages', methods=['GET', 'POST'])
def messages():
    if not session.get('email'):
        return need_login()
    u = current_user()

    if request.method == 'POST':
        subject = request.form.get('subject', '')
        body = request.form.get('message', '')
        msgs = load_data(MESSAGES_FILE)
        # VULNERABILITY: message stored exactly as submitted — no sanitization.
        msgs.append({
            "id": len(msgs) + 1,
            "from_email": u['email'],
            "from_name": u['name'],
            "subject": subject,
            "message": body,
            "ts": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        })
        save_data(MESSAGES_FILE, msgs)
        return redirect(url_for('messages'))

    mine = [m for m in load_data(MESSAGES_FILE) if m.get('from_email') == u['email']]
    # VULNERABILITY: templates render `message` with the |safe filter -> stored XSS.
    flag = None
    for m in mine:
        if XSS_SIG.search(m.get('message', '')):
            flag = 'warmup_stored_xss'
            break
    resp = make_response(render_template('messages.html', messages=mine,
                                         captured_flag=FLAGS[flag] if flag else None))
    if flag:
        issue_flag(flag, resp)
    return resp


# ----------------------------------------------------------------------------
# Search — VULNERABILITY #2: reflected XSS (unescaped echo)
# ----------------------------------------------------------------------------
@app.route('/search')
def search():
    if not session.get('email'):
        return need_login()
    q = request.args.get('q', '')
    # VULNERABILITY: q is echoed into the page with |safe in the template.
    flag = 'reflected_xss' if XSS_SIG.search(q) else None
    resp = make_response(render_template('search.html', q=q,
                                         captured_flag=FLAGS[flag] if flag else None))
    if flag:
        issue_flag(flag, resp)
    return resp


# ----------------------------------------------------------------------------
# Profile — VULNERABILITY #6: mass assignment on the profile API
# ----------------------------------------------------------------------------
@app.route('/profile')
def profile():
    if not session.get('email'):
        return need_login()
    return render_template('profile.html', user=current_user())


@app.route('/api/profile', methods=['PUT', 'POST'])
def api_profile():
    if not session.get('email'):
        return jsonify(error='login required'), 401
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify(error='send a JSON body'), 400

    users = load_data(USERS_FILE)
    user = current_user()
    if not user:
        return jsonify(error='no such user'), 401

    # VULNERABILITY: mass assignment — the API copies ANY field the client sends.
    # The editable set intentionally includes 'role' (and even 'password').
    EDITABLE = ('name', 'phone', 'email', 'role', 'password', 'title', 'allergies')
    for k, v in data.items():
        if k in EDITABLE:
            user[k] = v

    for i, u in enumerate(users):
        if u['id'] == user['id']:
            users[i] = user
            break
    save_data(USERS_FILE, users)

    # Keep the session email in sync if the client changed it.
    if 'email' in data:
        session['email'] = user['email']

    resp = jsonify({"ok": True, "role": user.get('role'), "email": user.get('email')})
    # If the client escalated their own role, that's the bug — award the flag.
    if user.get('role') == 'staff':
        issue_flag('mass_assignment', resp)
    return resp


# ----------------------------------------------------------------------------
# Staff area
# ----------------------------------------------------------------------------
@app.route('/staff')
def staff_home():
    # VULNERABILITY #5: only checks "logged in", NOT "is staff".
    # The link is simply not shown to patients — hiding ≠ protecting.
    if not session.get('email'):
        return need_login()
    u = current_user()
    flag = None
    if u.get('role') != 'staff':
        flag = 'bac_staff'
    stats = {
        "patients": sum(1 for x in load_data(USERS_FILE) if x.get('role') == 'patient'),
        "appointments": len(load_data(APPOINTMENTS_FILE)),
        "messages": len(load_data(MESSAGES_FILE)),
        "records": len(load_data(RECORDS_FILE)),
    }
    resp = make_response(render_template('staff.html', user=u,
                                         is_staff=u.get('role') == 'staff', stats=stats,
                                         captured_flag=FLAGS[flag] if flag else None))
    if flag:
        issue_flag(flag, resp)
    return resp


@app.route('/staff/patients')
def staff_patients():
    if not session.get('email'):
        return need_login()
    if not is_staff():
        return render_template('denied.html'), 403
    patients = [u for u in load_data(USERS_FILE) if u.get('role') == 'patient']
    records = load_data(RECORDS_FILE)
    return render_template('staff_patients.html', patients=patients, records=records)


@app.route('/staff/messages')
def staff_messages():
    if not session.get('email'):
        return need_login()
    if not is_staff():
        return render_template('denied.html'), 403
    msgs = load_data(MESSAGES_FILE)
    # The intended 'blind XSS' target: staff view renders patient messages raw.
    flag = None
    for m in msgs:
        if XSS_SIG.search(m.get('message', '')):
            flag = 'warmup_stored_xss'
            break
    resp = make_response(render_template('staff_messages.html', messages=msgs,
                                         captured_flag=FLAGS[flag] if flag else None))
    if flag:
        issue_flag(flag, resp)
    return resp


# ----------------------------------------------------------------------------
# Note preview — VULNERABILITY #10: DOM XSS (location.hash -> innerHTML)
# ----------------------------------------------------------------------------
@app.route('/preview')
def preview():
    return render_template('preview.html')


# ----------------------------------------------------------------------------
# XSS beacon — the explicit collection path for client-side XSS
# ----------------------------------------------------------------------------
@app.route('/api/beacon')
def beacon():
    cid = request.args.get('challenge') or request.headers.get('X-Challenge')
    if cid in ('warmup_stored_xss', 'reflected_xss', 'dom_xss'):
        register_solve(cid)
        return jsonify(ok=True, flag=FLAGS[cid])
    return jsonify(ok=False), 404


# ----------------------------------------------------------------------------
# Flag vault / progress dashboard — persistent, deadline countdown
# ----------------------------------------------------------------------------
@app.route('/vault', methods=['GET', 'POST'])
def vault():
    pid = g.pid
    message = None

    if request.method == 'POST':
        resume = request.form.get('player_id', '').strip()
        if resume:
            pid = resume
            resp = make_response(redirect(url_for('vault')))
            resp.set_cookie('player_id', resume, max_age=365 * 24 * 3600)
            return resp

    players = load_data(PLAYERS_FILE)
    solved = players.get(pid, {})
    deadline = load_data(DEADLINE_FILE)

    resp = make_response(render_template('vault.html', challenges=CHALLENGES,
                                         solved=solved, pid=pid,
                                         deadline=deadline))
    resp.set_cookie('player_id', pid, max_age=365 * 24 * 3600)
    return resp


@app.context_processor
def inject_globals():
    try:
        deadline = load_data(DEADLINE_FILE).get('deadline', '')
    except Exception:
        deadline = ''
    return dict(cu=current_user(), deadline_iso=deadline)


# ----------------------------------------------------------------------------
# Run
# ----------------------------------------------------------------------------
if __name__ == '__main__':
    print("\n" + "=" * 62)
    print("🏥  MediLink Health — 2026 CTF Lab")
    print("=" * 62)
    print(f"📍  Running at:  http://localhost:5000")
    print(f"👤  Demo patient: jordan@medilink.health / Jordan#2026")
    print(f"🔬  Challenges:   {len(CHALLENGES)} flags (MEDILINK{{...}})")
    print(f"📁  Progress:     saved in data/ — survives restarts forever")
    print(f"📅  Deadline:     {load_data(DEADLINE_FILE).get('label','')}")
    print("=" * 62 + "\n")
    # use_reloader=False keeps a single stable process (easy restart after edits).
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
