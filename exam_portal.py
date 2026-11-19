"""Kestrel Hill College Examination Integrity Portal (fictitious, local demo).

Integrates three controls around online exams: access control (student, examiner, invigilator and
administrator roles, bound to class and assigned exam), consent (monitoring signals only with the
student's agreement, with a manual-invigilation alternative), and audit (a hash-chained,
tamper-evident log). Integrity flags are advice for a human reviewer, never a verdict.

Run:  python3 exam_portal.py        (http://127.0.0.1:5005)
"""
import hashlib, math, os, re, secrets, sqlite3, time
from functools import wraps
from html import escape
from flask import Flask, Response, g, redirect, request, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
ON_VERCEL = bool(os.environ.get("VERCEL"))
DB_PATH = os.environ.get("PORTAL_DB", "/tmp/exam_portal.db" if ON_VERCEL else os.path.join(BASE, "exam_portal.db"))
app = Flask(__name__)
app.secret_key = os.environ.get("PORTAL_SECRET") or (hashlib.sha256(b"kestrel-exam-demo-secret").hexdigest() if ON_VERCEL else secrets.token_hex(24))
# BASELINE=1 starts a deliberately weak build (no hardening) so the scanner has a "before" to compare with.
BASELINE = os.environ.get("BASELINE") == "1"
app.config.update(SESSION_COOKIE_NAME="khc_exam_session", SESSION_COOKIE_HTTPONLY=not BASELINE,
                  SESSION_COOKIE_SAMESITE=None if BASELINE else "Strict")
ANALYTICS_SALT = os.environ.get("PORTAL_SALT", "kestrel-exam-demo-salt")

RECOMMENDED = {"audit_enabled": 1, "hash_chain": 1, "consent_enforced": 1,
               "lockout_threshold": 5, "session_timeout_min": 15, "min_password_len": 10}
LOCK_SECONDS = 300
GRACE = 60          # seconds allowed after the time limit before a submission is flagged as late
SIM_MIN = 3         # identical incorrect answers needed before a similarity review is suggested
FOCUS_MIN = 3       # focus-loss events needed before a review is suggested

# username, password, role, name, class
SEED = [
    ("admin", "Menon#Admin2026", "admin", "R. Menon", None),
    ("examiner1", "Rao!Exam2026", "examiner", "Ms. Rao", "10A"),
    ("examiner2", "Verma!Exam2026", "examiner", "Mr. Verma", "10B"),
    ("invig1", "Iyer!Watch2026", "invigilator", "Mr. Iyer", None),
    ("student1", "Aarav#Study2026", "student", "Aarav Shah", "10A"),
    ("student2", "Diya#Study2026", "student", "Diya Nair", "10B"),
    ("student3", "Kabir#Study2026", "student", "Kabir Mehta", "10A"),
    ("student4", "Isha#Study2026", "student", "Isha Patel", "10B"),
    ("student5", "Neel#Study2026", "student", "Neel Joshi", "10A"),
]
# exam id: (title, subject, class, examiner username, minutes, status, [(question, [A, B, C, D], correct)])
EXAMS = {
    1: ("Physics Unit Test", "Physics", "10A", "examiner1", 20, "open", [
        ("Which quantity is measured in newtons?", ["Mass", "Force", "Energy", "Power"], "B"),
        ("The SI unit of electric current is the", ["Volt", "Ohm", "Ampere", "Watt"], "C"),
        ("Light travels fastest in", ["Vacuum", "Water", "Glass", "Air"], "A"),
        ("Which is a vector quantity?", ["Speed", "Distance", "Time", "Velocity"], "D"),
        ("A convex lens is also called a", ["Diverging lens", "Converging lens", "Plane mirror", "Prism"], "B")]),
    2: ("Mathematics Unit Test", "Mathematics", "10B", "examiner2", 20, "open", [
        ("The value of 7 x 8 is", ["54", "58", "56", "64"], "C"),
        ("The square root of 144 is", ["12", "14", "16", "10"], "A"),
        ("The sum of angles in a triangle is", ["90 degrees", "270 degrees", "360 degrees", "180 degrees"], "D"),
        ("Which number is prime?", ["9", "13", "15", "21"], "B"),
        ("If x + 5 = 12, then x is", ["7", "5", "17", "6"], "A")]),
    3: ("English Mid-term", "English", "10A", "examiner1", 20, "closed", [
        ("Choose the correct spelling.", ["Necessary", "Neccessary", "Necesary", "Nesessary"], "A"),
        ("A word opposite in meaning is called a", ["Synonym", "Homonym", "Antonym", "Acronym"], "C"),
        ("Pick the noun in: 'The river flows fast.'", ["flows", "river", "fast", "the"], "B"),
        ("Which sentence is in the past tense?", ["She sings.", "She will sing.", "She is singing.", "She sang."], "D"),
        ("A group of words with a subject and verb is a", ["Clause", "Letter", "Prefix", "Stanza"], "A")]),
}
# seeded history for the closed exam: user, answers, seconds used, focus-loss events
HISTORY = [("student1", "ADBCB", 230, 0), ("student3", "ABCAC", 1020, 3), ("student5", "ABCAD", 980, 0)]
CONSENT_SEED = {"student1": (1, 1), "student2": (1, 1), "student3": (1, 0), "student4": (0, 1), "student5": (1, 1)}  # signals, analytics


# ------------------------------------------------------------------ data layer
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def q(sql, args=(), one=False):
    cur = db().execute(sql, args)
    rows = cur.fetchall()
    db().commit()
    return (rows[0] if rows else None) if one else rows


@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    c = sqlite3.connect(DB_PATH)
    c.executescript("""
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT, role TEXT, name TEXT, class_id TEXT);
    CREATE TABLE exams(id INTEGER PRIMARY KEY, title TEXT, subject TEXT, class_id TEXT, examiner_id INT, duration_min INT, status TEXT);
    CREATE TABLE questions(exam_id INT, qno INT, text TEXT, options TEXT, correct TEXT);
    CREATE TABLE attempts(id INTEGER PRIMARY KEY, exam_id INT, student_id INT, started REAL, submitted REAL, score INT,
        mode TEXT, appeal INT DEFAULT 0);
    CREATE TABLE answers(attempt_id INT, qno INT, choice TEXT);
    CREATE TABLE events(id INTEGER PRIMARY KEY, attempt_id INT, ts REAL, kind TEXT);
    CREATE TABLE flags(id INTEGER PRIMARY KEY, attempt_id INT, rule TEXT, detail TEXT, status TEXT DEFAULT 'open',
        decided_by TEXT, decided_ts REAL);
    CREATE TABLE assign(exam_id INT, invigilator_id INT);
    CREATE TABLE consents(student_id INT, purpose TEXT, granted INT, updated TEXT, PRIMARY KEY(student_id, purpose));
    CREATE TABLE audit(id INTEGER PRIMARY KEY, ts REAL, actor TEXT, role TEXT, action TEXT, target TEXT, outcome TEXT,
        detail TEXT, prev TEXT DEFAULT '', hash TEXT DEFAULT '');
    CREATE TABLE settings(k TEXT PRIMARY KEY, v INT);
    CREATE TABLE lockouts(username TEXT PRIMARY KEY, fails INT, last REAL);
    CREATE TABLE score_log(id INTEGER PRIMARY KEY, ts REAL, score INT, met INT, total INT, note TEXT);
    """)
    ids = {}
    for u in SEED:
        cur = c.execute("INSERT INTO users(username,pw_hash,role,name,class_id) VALUES(?,?,?,?,?)",
                        (u[0], generate_password_hash(u[1]), u[2], u[3], u[4]))
        ids[u[0]] = cur.lastrowid
    for eid, (title, subj, cls, exr, mins, status, qs) in EXAMS.items():
        c.execute("INSERT INTO exams VALUES(?,?,?,?,?,?,?)", (eid, title, subj, cls, ids[exr], mins, status))
        for i, (t, opts, ans) in enumerate(qs, 1):
            c.execute("INSERT INTO questions VALUES(?,?,?,?,?)", (eid, i, t, "|".join(opts), ans))
        c.execute("INSERT INTO assign VALUES(?,?)", (eid, ids["invig1"]))
    for name, (sig, ana) in CONSENT_SEED.items():
        c.execute("INSERT INTO consents VALUES(?,?,?,?)", (ids[name], "proctoring_signals", sig, "2026-08-04"))
        c.execute("INSERT INTO consents VALUES(?,?,?,?)", (ids[name], "analytics", ana, "2026-08-04"))
    base = time.time() - 86400 * 3
    correct = "ADBCA"
    for name, ans, used, focus in HISTORY:
        mode = "signals"
        score = sum(1 for a, k in zip(ans, correct) if a == k)
        cur = c.execute("INSERT INTO attempts(exam_id,student_id,started,submitted,score,mode) VALUES(3,?,?,?,?,?)",
                        (ids[name], base, base + used, score, mode))
        for i, a in enumerate(ans, 1):
            c.execute("INSERT INTO answers VALUES(?,?,?)", (cur.lastrowid, i, a))
        for k in range(focus):
            c.execute("INSERT INTO events(attempt_id,ts,kind) VALUES(?,?,'focus_lost')", (cur.lastrowid, base + 100 + k * 60))
    start = dict(RECOMMENDED)
    if BASELINE:
        start.update(lockout_threshold=0, hash_chain=0, consent_enforced=0)
    for k, v in start.items():
        c.execute("INSERT INTO settings VALUES(?,?)", (k, v))
    c.commit()
    c.close()
    with app.app_context():
        for r in q("SELECT id FROM attempts ORDER BY id"):
            compute_flags(r["id"])
        q("UPDATE flags SET status='cleared', decided_by='examiner1', decided_ts=? WHERE rule='unusually_fast'", (base + 86400,))


def setting(k):
    r = q("SELECT v FROM settings WHERE k=?", (k,), True)
    return int(r["v"]) if r else RECOMMENDED[k]


def actor():
    if "uid" not in session:
        return None
    return q("SELECT * FROM users WHERE id=?", (session["uid"],), True)


# ---- audit log with hash chain (each entry commits to the one before it)
def chain_hash(prev, ts, actor_, role, action, target, outcome, detail):
    text = "|".join([prev, repr(float(ts)), actor_, role, action, target, outcome, detail])
    return hashlib.sha256(text.encode()).hexdigest()


def audit(action, target="", outcome="allowed", detail=""):
    if not setting("audit_enabled"):
        return
    ts, who, role = time.time(), session.get("username", "anonymous"), session.get("role", "none")
    prev = h = ""
    if setting("hash_chain"):
        last = q("SELECT hash FROM audit WHERE hash!='' ORDER BY id DESC LIMIT 1", (), True)
        prev = last["hash"] if last else "GENESIS"
        h = chain_hash(prev, ts, who, role, action, target, outcome, detail)
    q("INSERT INTO audit(ts,actor,role,action,target,outcome,detail,prev,hash) VALUES(?,?,?,?,?,?,?,?,?)",
      (ts, who, role, action, target, outcome, detail, prev, h))


def verify_chain(rows=None):
    """Returns (intact, first_bad_entry_id, entries_checked)."""
    rows = rows if rows is not None else q("SELECT * FROM audit ORDER BY id")
    last, n = "GENESIS", 0
    for r in rows:
        if not r["hash"]:
            continue
        if r["prev"] != last or chain_hash(r["prev"], r["ts"], r["actor"], r["role"], r["action"], r["target"],
                                           r["outcome"], r["detail"]) != r["hash"]:
            return False, r["id"], n
        last, n = r["hash"], n + 1
    return True, None, n


# ---- exam helpers
RULE_TEXT = {
    "answer_similarity": ("Answer similarity", "Several incorrect answers match another candidate's. Similar answers can happen by chance; a person decides."),
    "unusually_fast": ("Unusually fast finish", "The paper was finished much faster than usual with a high score."),
    "focus_changes": ("Repeated focus changes", "The exam window lost focus several times (only recorded with your consent)."),
    "late_submission": ("Late submission", "The paper was submitted after the time limit."),
}


def exam_row(eid):
    return q("SELECT * FROM exams WHERE id=?", (eid,), True)


def attempt_row(aid):
    return q("SELECT * FROM attempts WHERE id=?", (aid,), True)


def has_consent(sid, purpose):
    r = q("SELECT granted FROM consents WHERE student_id=? AND purpose=?", (sid, purpose), True)
    return bool(r and r["granted"])


def n_questions(eid):
    return q("SELECT COUNT(*) c FROM questions WHERE exam_id=?", (eid,), True)["c"]


def pseudo(sid):
    return "S-" + hashlib.sha256((ANALYTICS_SALT + str(sid)).encode()).hexdigest()[:8]


def compute_flags(aid):
    a = attempt_row(aid)
    if not a or a["submitted"] is None:
        return []
    ex, n = exam_row(a["exam_id"]), n_questions(a["exam_id"])
    allowed, used = ex["duration_min"] * 60, a["submitted"] - a["started"]
    found = []
    if used > allowed + GRACE:
        found.append(("late_submission", f"Submitted {int(used - allowed)} s after the time limit"))
    if a["score"] is not None and a["score"] / n >= 0.8 and used < 0.25 * allowed:
        found.append(("unusually_fast", f"Score {a['score']} of {n} in {int(used)} s of {allowed} s allowed"))
    if a["mode"] == "signals":
        k = q("SELECT COUNT(*) c FROM events WHERE attempt_id=? AND kind='focus_lost'", (aid,), True)["c"]
        if k >= FOCUS_MIN:
            found.append(("focus_changes", f"{k} focus-loss events during the attempt"))
    corr = {r["qno"]: r["correct"] for r in q("SELECT qno, correct FROM questions WHERE exam_id=?", (a["exam_id"],))}
    mine = {r["qno"]: r["choice"] for r in q("SELECT * FROM answers WHERE attempt_id=?", (aid,))}
    for o in q("SELECT id FROM attempts WHERE exam_id=? AND id<? AND submitted IS NOT NULL", (a["exam_id"], aid)):
        theirs = {r["qno"]: r["choice"] for r in q("SELECT * FROM answers WHERE attempt_id=?", (o["id"],))}
        shared = [k for k, c in mine.items() if c and c != corr.get(k) and theirs.get(k) == c]
        if len(shared) >= SIM_MIN:
            found.append(("answer_similarity", f"{len(shared)} identical incorrect answers (questions {', '.join(map(str, shared))}) shared with attempt #{o['id']}"))
    for rule, detail in found:
        if not q("SELECT 1 FROM flags WHERE attempt_id=? AND rule=?", (aid, rule), True):
            q("INSERT INTO flags(attempt_id,rule,detail) VALUES(?,?,?)", (aid, rule, detail))
    return found


def result_cell(outcome, allowed_text="allowed"):
    return '<span class="denied">denied</span>' if outcome == "denied" else allowed_text


def status_cell(ok):
    return '<span class="met">Met</span>' if ok else '<span class="notmet">Not met</span>'


def when(ts):
    return time.strftime("%d %b %Y, %H:%M:%S", time.localtime(ts))


# ------------------------------------------------------------------ presentation
CSS = """
*{box-sizing:border-box}
body{margin:0;background:#fbfaf6;color:#1e1e1c;font:17px/1.55 Calibri,Carlito,sans-serif}
header{background:#1b3a4b;color:#f4efe3;padding:12px 32px;display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px}
header .name{font:600 22px Charter,'Bitstream Charter',Georgia,serif}
header .sub{font-size:14px;margin-left:12px;opacity:.85}
nav{display:flex;gap:20px;align-items:baseline;flex-wrap:wrap;font-size:15px}
nav a,nav button{color:#f4efe3;background:none;border:0;padding:0;margin:0;font:inherit;text-decoration:underline;cursor:pointer}
nav form{display:inline;margin:0}
main{max-width:980px;margin:0 auto;padding:28px 32px 56px}
h1{font:600 28px Charter,'Bitstream Charter',Georgia,serif;margin:4px 0 16px}
h2{font:600 20px Charter,'Bitstream Charter',Georgia,serif;margin:28px 0 8px}
table{border-collapse:collapse;width:100%;margin:8px 0 16px;font-size:16px}
th,td{border:1px solid #bdb7a8;padding:6px 10px;text-align:left;vertical-align:top}
th{background:#ece7da;font-weight:600}
label{display:block;font-weight:600;margin:14px 0 4px}
input[type=text],input[type=password],input[type=number]{width:100%;max-width:380px;padding:8px 10px;font:inherit;border:1px solid #8c8677;background:#fff}
input[type=number]{max-width:120px}
button.main{margin-top:16px;padding:9px 22px;font:600 16px Calibri,Carlito,sans-serif;background:#1b3a4b;color:#f4efe3;border:0;border-radius:2px;cursor:pointer}
button.plain{padding:6px 14px;font:600 15px Calibri,Carlito,sans-serif;background:#ece7da;color:#1b3a4b;border:1px solid #8c8677;border-radius:2px;cursor:pointer}
a{color:#0b5c8a}
.error{border:1px solid #9b2c2c;background:#f8e9e6;color:#6f1d1d;padding:8px 12px;max-width:520px;margin:14px 0}
.info{border:1px solid #2f6b4f;background:#e7f2ec;color:#1d4a35;padding:8px 12px;max-width:620px;margin:14px 0}
.note{border-left:3px solid #8c8677;padding:2px 14px;margin:18px 0;color:#4a473f;font-size:15px}
.cols{display:flex;gap:44px;flex-wrap:wrap}.cols>div{flex:1;min-width:280px}
.met{color:#1d4a35;background:#e7f2ec;padding:1px 8px;font-weight:600;font-size:14px}
.notmet{color:#6f1d1d;background:#f8e9e6;padding:1px 8px;font-weight:600;font-size:14px}
.denied{color:#6f1d1d;font-weight:600}
.big{font:600 40px Charter,'Bitstream Charter',Georgia,serif}
dl{display:grid;grid-template-columns:170px 1fr;gap:6px 12px;margin:8px 0 16px}dt{font-weight:600}dd{margin:0}
.check{display:flex;gap:10px;align-items:center;margin:8px 0;font-weight:600}.check input{width:auto}
.grid2{display:flex;gap:40px;flex-wrap:wrap}.grid2>div{flex:1;min-width:420px}
.kpi td{font:600 26px Charter,'Bitstream Charter',Georgia,serif;border:1px solid #bdb7a8;padding:8px 12px}
.kpi th{font-size:14px}
.steps td.ok{color:#1d4a35;font-weight:600}.steps td.bad{color:#6f1d1d;font-weight:600}
.verdict{font:600 22px Charter,'Bitstream Charter',Georgia,serif;margin:14px 0}
.track{background:#ddd5c4;height:10px;margin:14px 0 6px}.fill{background:#1b3a4b;height:10px;width:0}
.frag{margin:22px 0;border-top:1px solid #bdb7a8}
fieldset{border:1px solid #bdb7a8;margin:14px 0;padding:8px 16px 12px;background:#fff}
legend{font-weight:600;padding:0 6px}
.opt{display:block;font-weight:400;margin:6px 0}
select{padding:7px 10px;font:inherit;border:1px solid #8c8677;background:#fff}
footer{max-width:980px;margin:0 auto;padding:0 32px 28px;font-size:13px;color:#6b675c}
"""
FAVICON = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' fill='#1b3a4b'/>"
           "<path d='M8 7h4v7l7-7h5l-8 8 8 10h-5l-6-8v8H8z' fill='#f4efe3'/></svg>")
STRENGTH_JS = """(function(){var p=document.getElementById('np'),o=document.getElementById('strength');if(!p||!o)return;
p.addEventListener('input',function(){var v=p.value,s=0;if(v.length>=10)s++;if(/[a-z]/.test(v))s++;if(/[A-Z]/.test(v))s++;
if(/[0-9]/.test(v))s++;if(/[^A-Za-z0-9]/.test(v))s++;o.textContent=['Very weak','Very weak','Weak','Fair','Good','Strong'][s]+' ('+s+' of 5 rules met)';});})();"""


@app.route("/portal.css")
def css():
    return Response(CSS, mimetype="text/css")


@app.route("/favicon.svg")
def favicon():
    return Response(FAVICON, mimetype="image/svg+xml")


@app.route("/strength.js")
def strength_js():
    return Response(STRENGTH_JS, mimetype="application/javascript")


def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return f'<input type="hidden" name="csrf" value="{session["csrf"]}">'


def nav_for(u):
    if not u:
        return ""
    links = [("/dashboard", "Dashboard")]
    if u["role"] == "student":
        links += [("/my/privacy", "Privacy and consent"), ("/my/access-log", "Who viewed my results")]
    if u["role"] == "admin":
        links += [("/admin/audit", "Audit log"), ("/admin/privacy", "Privacy settings"), ("/admin/analytics", "Analytics"),
                  ("/admin/users", "Users"), ("/demo", "Guided demo"), ("/showcase", "Live showcase")]
    links.append(("/account/password", "Password"))
    items = "".join(f'<a href="{h}">{escape(t)}</a>' for h, t in links)
    return (f'<nav>{items}<form method="post" action="/logout">{csrf()}<button type="submit">Sign out ({escape(u["username"])})</button></form></nav>')


def page(title, body, u=None, code=200):
    msg = session.pop("msg", None)
    flash = f'<div class="info">{escape(msg)}</div>' if msg else ""
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)} | Kestrel Hill College</title>
<link rel="icon" href="/favicon.svg"><link rel="stylesheet" href="/portal.css"></head><body>
<header><div><span class="name">Kestrel Hill College</span><span class="sub">Examination Portal</span></div>{nav_for(u)}</header>
<main>{flash}{body}</main>
<footer>Demonstration system for an examination integrity project. All people, addresses and numbers are fictitious.</footer>
<script src="/strength.js"></script></body></html>"""
    return Response(html, status=code, mimetype="text/html")


def denied_page(u, why="You do not have permission to open this page."):
    return page("Access denied", f"<h1>Access denied</h1><p>{escape(why)}</p><p>This attempt has been recorded.</p>"
                '<p><a href="/dashboard">Back to dashboard</a></p>', u, 403)


@app.after_request
def headers(r):
    if BASELINE:
        return r
    r.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "no-referrer"
    if "uid" in session:
        r.headers["Cache-Control"] = "no-store"
    return r


@app.before_request
def guard():
    if request.endpoint in ("css", "favicon", "strength_js", "exam_js"):
        return None
    if "uid" in session:
        now = time.time()
        if now - session.get("last", now) > setting("session_timeout_min") * 60:
            audit("session_timeout", "", "denied", "idle limit reached")
            session.clear()
            session["msg"] = "Your session ended after a period of inactivity. Please sign in again."
            return redirect("/")
        session["last"] = now
    if request.method == "POST":
        tok = request.form.get("csrf", "")
        if not session.get("csrf") or not secrets.compare_digest(tok, session["csrf"]):
            audit("csrf_rejected", request.path, "denied")
            return page("Request rejected", "<h1>Request rejected</h1><p>The form could not be verified. "
                        'Reload the page and try again.</p>', actor(), 400)
    return None


def need(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            u = actor()
            if not u:
                audit("open_page", request.path, "denied", "not signed in")
                return redirect("/")
            if roles and u["role"] not in roles:
                audit("open_page", request.path, "denied", f"role {u['role']} not permitted")
                return denied_page(u)
            return f(u, *a, **k)
        return w
    return deco



# ------------------------------------------------------------------ charts (server-side SVG, no scripts)
INK, RED, SAND, MUTED, TXT = "#1b3a4b", "#9b2c2c", "#d9d3c4", "#8c8677", "#1e1e1c"


def svg(w, h, body, label):
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="{escape(label)}" '
            f'font-family="Calibri, Carlito, sans-serif" font-size="14">{body}</svg>')


def stacked_bars(rows, label, w=480):
    if not rows:
        return '<p class="note">No events yet.</p>'
    lab, right = 150, 50
    mx = max(a + d for _, a, d in rows) or 1
    scale = (w - lab - right) / mx
    h = 34 + len(rows) * 28
    b = (f'<rect x="{lab}" y="4" width="12" height="12" fill="{INK}"/><text x="{lab+18}" y="15" fill="{TXT}">allowed</text>'
         f'<rect x="{lab+90}" y="4" width="12" height="12" fill="{RED}"/><text x="{lab+108}" y="15" fill="{TXT}">denied</text>')
    for i, (n, a, d) in enumerate(rows):
        y = 28 + i * 28
        b += f'<text x="{lab-8}" y="{y+15}" text-anchor="end" fill="{TXT}">{escape(n)}</text>'
        b += f'<rect x="{lab}" y="{y}" width="{a*scale:.1f}" height="20" fill="{INK}"/>'
        b += f'<rect x="{lab+a*scale:.1f}" y="{y}" width="{d*scale:.1f}" height="20" fill="{RED}"/>'
        b += f'<text x="{lab+(a+d)*scale+8:.1f}" y="{y+15}" fill="{TXT}">{a+d}</text>'
    return svg(w, h, b, label)


def hbars(rows, label, w=440, maxv=100):
    lab = 150
    scale = (w - lab - 50) / maxv
    h = 8 + len(rows) * 30
    b = ""
    for i, (n, v) in enumerate(rows):
        y = 6 + i * 30
        b += f'<text x="{lab-8}" y="{y+16}" text-anchor="end" fill="{TXT}">{escape(n)}</text>'
        b += f'<rect x="{lab}" y="{y}" width="{maxv*scale:.1f}" height="22" fill="{SAND}"/>'
        b += f'<rect x="{lab}" y="{y}" width="{v*scale:.1f}" height="22" fill="{INK}"/>'
        b += f'<text x="{lab+maxv*scale+8:.1f}" y="{y+16}" fill="{TXT}">{v}</text>'
    return svg(w, h, b, label)


def mini_bar(v, w=130):
    return (f'<svg width="{w}" height="14" viewBox="0 0 {w} 14" role="img" aria-label="score {v}"><rect width="{w}" height="14" fill="{SAND}"/>'
            f'<rect width="{w*v/100:.1f}" height="14" fill="{INK}"/></svg>')


def line_chart(vals, label, w=480, h=230):
    L, R, T, B = 50, 40, 26, 36
    pw, ph = w - L - R, h - T - B
    b = ""
    for gv in (0, 25, 50, 75, 100):
        y = T + ph * (1 - gv / 100)
        b += f'<line x1="{L}" y1="{y:.1f}" x2="{w-R}" y2="{y:.1f}" stroke="{SAND}"/><text x="{L-8}" y="{y+4:.1f}" text-anchor="end" fill="{TXT}">{gv}</text>'
    n = len(vals)
    inset = 24
    pts = [(L + inset + ((pw - 2 * inset) * i / (n - 1) if n > 1 else (pw - 2 * inset) / 2), T + ph * (1 - v / 100)) for i, v in enumerate(vals)]
    if n > 1:
        b += f'<polyline fill="none" stroke="{INK}" stroke-width="2.5" points="{" ".join(f"{x:.1f},{y:.1f}" for x, y in pts)}"/>'
    for i, ((x, y), v) in enumerate(zip(pts, vals)):
        b += f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{INK}"/><text x="{x:.1f}" y="{y-11:.1f}" text-anchor="middle" fill="{TXT}">{v}%</text>'
        b += f'<text x="{x:.1f}" y="{h-12}" text-anchor="middle" fill="{TXT}">check {i+1}</text>'
    return svg(w, h, b, label)


def donut(parts, label, w=480, h=190):
    tot = sum(v for _, v, _ in parts) or 1
    ro, ri, cx, cy = 74, 46, 90, 95
    b = ""
    a0 = -math.pi / 2
    for _, v, col in parts:
        if not v:
            continue
        if v == tot:
            b += f'<circle cx="{cx}" cy="{cy}" r="{(ro+ri)/2}" fill="none" stroke="{col}" stroke-width="{ro-ri}"/>'
            continue
        a1 = a0 + 2 * math.pi * v / tot
        big = 1 if a1 - a0 > math.pi else 0
        p = lambda r_, a_: (cx + r_ * math.cos(a_), cy + r_ * math.sin(a_))
        (x0, y0), (x1, y1), (x2, y2), (x3, y3) = p(ro, a0), p(ro, a1), p(ri, a1), p(ri, a0)
        b += (f'<path d="M{x0:.2f},{y0:.2f} A{ro},{ro} 0 {big} 1 {x1:.2f},{y1:.2f} L{x2:.2f},{y2:.2f} A{ri},{ri} 0 {big} 0 {x3:.2f},{y3:.2f} Z" '
              f'fill="{col}" stroke="#fbfaf6" stroke-width="2"/>')
        a0 = a1
    b += f'<text x="{cx}" y="{cy+9}" text-anchor="middle" font-size="26" font-weight="700" fill="{TXT}">{sum(v for _, v, _ in parts)}</text>'
    for i, (n, v, col) in enumerate(parts):
        y = 55 + i * 32
        b += f'<rect x="190" y="{y-12}" width="14" height="14" fill="{col}"/><text x="212" y="{y}" fill="{TXT}">{escape(n)}: {v}</text>'
    return svg(w, h, b, label)


def log_score(note=""):
    ck = compliance()
    met = sum(1 for c in ck if c[1])
    q("INSERT INTO score_log(ts,score,met,total,note) VALUES(?,?,?,?,?)", (time.time(), round(100 * met / len(ck)), met, len(ck), note))


# ------------------------------------------------------------------ authentication
DUMMY = generate_password_hash("dummy-password-for-timing")


@app.route("/")
def home():
    if "uid" in session:
        return redirect("/dashboard")
    rows = "".join(f"<tr><td>{u[0]}</td><td>{u[1]}</td><td>{u[2]}</td></tr>" for u in SEED)
    body = f"""<div class="cols"><div><h1>Sign in</h1>
<p>Use your college username and password to see your exams, results and privacy choices.</p>
<form method="post" action="/signin">{csrf()}
<label for="u">Username</label><input type="text" id="u" name="username" autocomplete="off">
<label for="p">Password</label><input type="password" id="p" name="password" autocomplete="off">
<button class="main" type="submit">Sign in</button></form></div>
<div><h2>Demonstration accounts</h2><table><tr><th>Username</th><th>Password</th><th>Role</th></tr>{rows}</table>
<p class="note">These accounts exist only in this test system so that assessors can reproduce the tests.</p></div></div>"""
    return page("Sign in", body)


@app.route("/signin", methods=["POST"])
def signin():
    name, pw = request.form.get("username", "").strip(), request.form.get("password", "")
    lock = q("SELECT * FROM lockouts WHERE username=?", (name,), True)
    thr = setting("lockout_threshold")
    if thr and lock and lock["fails"] >= thr and time.time() - lock["last"] < LOCK_SECONDS:
        left = int((LOCK_SECONDS - (time.time() - lock["last"])) // 60) + 1
        session["username"] = name
        audit("login", name, "denied", "account locked")
        session.pop("username", None)
        return page("Sign in", f'<h1>Sign in</h1><div class="error">Too many unsuccessful attempts. Try again in about {left} minutes.</div>'
                    '<p><a href="/">Back to sign in</a></p>', None, 429)
    row = q("SELECT * FROM users WHERE username=?", (name,), True)
    ok = check_password_hash(row["pw_hash"] if row else DUMMY, pw) and row is not None
    if not ok:
        n = (lock["fails"] + 1) if lock and time.time() - lock["last"] < LOCK_SECONDS else 1
        q("INSERT OR REPLACE INTO lockouts VALUES(?,?,?)", (name, n, time.time()))
        session["username"] = name
        audit("login", name, "denied", "invalid credentials")
        session.pop("username", None)
        return page("Sign in", '<h1>Sign in</h1><div class="error">Invalid username or password.</div><p><a href="/">Try again</a></p>', None, 401)
    q("DELETE FROM lockouts WHERE username=?", (name,))
    session.clear()
    session.update(uid=row["id"], username=row["username"], role=row["role"], last=time.time())
    audit("login", name, "allowed")
    return redirect("/showcase" if (row["role"] == "admin" and os.environ.get("SHOWCASE") == "1") else "/dashboard")


@app.route("/logout", methods=["POST"])
def logout():
    audit("logout", session.get("username", ""))
    session.clear()
    return redirect("/")


@app.route("/account/password", methods=["GET", "POST"])
@need()
def password(u):
    err = ""
    if request.method == "POST":
        cur, new, conf = (request.form.get(k, "") for k in ("current", "new", "confirm"))
        rules = []
        if len(new) < setting("min_password_len"): rules.append(f"at least {setting('min_password_len')} characters")
        if not re.search(r"[a-z]", new): rules.append("a lower-case letter")
        if not re.search(r"[A-Z]", new): rules.append("an upper-case letter")
        if not re.search(r"\d", new): rules.append("a digit")
        if not re.search(r"[^A-Za-z0-9]", new): rules.append("a symbol")
        if u["username"].lower() in new.lower(): rules.append("no part of your username")
        if not check_password_hash(u["pw_hash"], cur):
            err = "The current password is not correct."
        elif new != conf:
            err = "The new passwords do not match."
        elif rules:
            err = "The new password needs: " + ", ".join(rules) + "."
        if err:
            audit("password_change", u["username"], "denied", err[:60])
            return page("Change password", form_password(err), u, 400)
        q("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(new), u["id"]))
        audit("password_change", u["username"], "allowed")
        session["msg"] = "Password changed."
        return redirect("/dashboard")
    return page("Change password", form_password(), u)


def form_password(err=""):
    e = f'<div class="error">{escape(err)}</div>' if err else ""
    return f"""<h1>Change password</h1>{e}<form method="post" action="/account/password">{csrf()}
<label for="cp">Current password</label><input type="password" id="cp" name="current" autocomplete="off">
<label for="np">New password</label><input type="password" id="np" name="new" autocomplete="off">
<p id="strength" class="note">Strength: type a new password</p>
<label for="cf">Confirm new password</label><input type="password" id="cf" name="confirm" autocomplete="off">
<button class="main" type="submit">Save password</button></form>
<p class="note">Rules: minimum length set by the administrator, upper and lower case, a digit, a symbol, and no part of your username.</p>"""


# ------------------------------------------------------------------ dashboards
EXAM_JS = """(function(){var e=document.getElementById('exam');if(!e||e.dataset.signals!=='1')return;
function send(kind){var b=new URLSearchParams();b.set('csrf',e.dataset.csrf);b.set('kind',kind);
fetch('/attempt/'+e.dataset.attempt+'/event',{method:'POST',body:b,credentials:'same-origin'});}
document.addEventListener('visibilitychange',function(){if(document.hidden)send('focus_lost');});})();"""


@app.route("/exam.js")
def exam_js():
    return Response(EXAM_JS, mimetype="application/javascript")


def student_exams(u):
    return q("SELECT * FROM exams WHERE class_id=? ORDER BY id", (u["class_id"],))


def pct(score, n):
    return round(100 * score / n) if n else 0


@app.route("/dashboard")
@need()
def dashboard(u):
    if u["role"] == "student":
        rows, scores = "", []
        for ex in student_exams(u):
            at = q("SELECT * FROM attempts WHERE exam_id=? AND student_id=?", (ex["id"], u["id"]), True)
            if at and at["submitted"]:
                act = f'<a href="/attempt/{at["id"]}/result">View result</a>'
                scores.append((ex["title"], pct(at["score"], n_questions(ex["id"]))))
            elif at:
                act = f'<a href="/attempt/{at["id"]}">Resume</a>'
            elif ex["status"] == "open":
                act = f'<a href="/exam/{ex["id"]}">Start</a>'
            else:
                act = "Closed"
            rows += (f'<tr><td>{escape(ex["title"])}</td><td>{escape(ex["subject"])}</td><td>{ex["duration_min"]} min</td>'
                     f'<td>{ex["status"].capitalize()}</td><td>{act}</td></tr>')
        sig, ana = has_consent(u["id"], "proctoring_signals"), has_consent(u["id"], "analytics")
        nf = q("SELECT COUNT(*) c FROM flags f JOIN attempts a ON a.id=f.attempt_id WHERE a.student_id=?", (u["id"],), True)["c"]
        tgt = f"student:{u['id']}"
        seen = q("SELECT COUNT(*) c FROM audit WHERE target=? AND action='view_attempt' AND outcome='allowed'", (tgt,), True)["c"]
        refused = q("SELECT COUNT(*) c FROM audit WHERE target=? AND action='view_attempt' AND outcome='denied'", (tgt,), True)["c"]
        body = (f'<h1>Welcome, {escape(u["name"])}</h1><p>Class {escape(u["class_id"])}</p>'
                f'<h2>Your exams</h2><table><tr><th>Exam</th><th>Subject</th><th>Time</th><th>Status</th><th></th></tr>{rows or "<tr><td colspan=5>No exams.</td></tr>"}</table>'
                f'<div class="grid2"><div><h2>Your results</h2>{hbars(scores, "Your score in each completed exam") if scores else "<p class=note>No completed exams yet.</p>"}</div>'
                f'<div><h2>Your privacy snapshot</h2><table><tr><th>Item</th><th>Status</th></tr>'
                f'<tr><td>Monitoring signals allowed</td><td>{"Yes" if sig else "No, manual invigilation"}</td></tr>'
                f'<tr><td>Included in anonymised analytics</td><td>{"Yes" if ana else "No"}</td></tr>'
                f'<tr><td>Integrity notes on my attempts</td><td>{nf}</td></tr></table>'
                f'{stacked_bars([("Opened by staff", seen, 0), ("Refused attempts", 0, refused)], "Access to your results")}</div></div>'
                '<p><a href="/my/privacy">Privacy and consent</a> | <a href="/my/access-log">Who viewed my results</a></p>')
        return page("Dashboard", body, u)
    if u["role"] == "examiner":
        rows = ""
        for ex in q("SELECT * FROM exams WHERE examiner_id=? ORDER BY id", (u["id"],)):
            na = q("SELECT COUNT(*) c FROM attempts WHERE exam_id=? AND submitted IS NOT NULL", (ex["id"],), True)["c"]
            nfo = q("SELECT COUNT(*) c FROM flags f JOIN attempts a ON a.id=f.attempt_id WHERE a.exam_id=? AND f.status='open'", (ex["id"],), True)["c"]
            rows += (f'<tr><td>{escape(ex["title"])}</td><td>{escape(ex["class_id"])}</td><td>{ex["status"].capitalize()}</td>'
                     f'<td>{na}</td><td>{nfo}</td><td><a href="/exam/{ex["id"]}/review">Review</a></td></tr>')
        body = (f'<h1>Your exams</h1><p>{escape(u["name"])}, class {escape(u["class_id"])}. You can open papers and results only for exams you set.</p>'
                f'<table><tr><th>Exam</th><th>Class</th><th>Status</th><th>Submitted</th><th>Flags to review</th><th></th></tr>{rows}</table>')
        return page("Dashboard", body, u)
    if u["role"] == "invigilator":
        rows = "".join(f'<tr><td>{escape(e["title"])}</td><td>{escape(e["class_id"])}</td><td>{e["status"].capitalize()}</td>'
                       f'<td><a href="/invigilate/{e["id"]}">Open hall view</a></td></tr>'
                       for e in q("SELECT e.* FROM exams e JOIN assign a ON a.exam_id=e.id WHERE a.invigilator_id=? ORDER BY e.id", (u["id"],)))
        body = (f'<h1>Your exam halls</h1><p>{escape(u["name"])}. You see who is sitting and the monitoring status. You do not see answers or scores.</p>'
                f'<table><tr><th>Exam</th><th>Class</th><th>Status</th><th></th></tr>{rows}</table>')
        return page("Dashboard", body, u)
    # administrator
    cnt = lambda sql: q(sql, (), True)["c"]
    ok, bad, n_chk = verify_chain()
    ck = compliance()
    met = sum(1 for c in ck if c[1])
    kpi = (f'<table class="kpi"><tr><th>Exams</th><th>Submitted attempts</th><th>Flags to review</th><th>Audit entries</th><th>Audit chain</th><th>Compliance</th></tr>'
           f'<tr><td>{cnt("SELECT COUNT(*) c FROM exams")}</td><td>{cnt("SELECT COUNT(*) c FROM attempts WHERE submitted IS NOT NULL")}</td>'
           f'<td>{cnt("SELECT COUNT(*) c FROM flags WHERE status=\'open\'")}</td><td>{cnt("SELECT COUNT(*) c FROM audit")}</td>'
           f'<td>{"Intact" if ok else "Broken"}</td><td>{round(100 * met / len(ck))}%</td></tr></table>')
    by_action = [(r["action"].replace("_", " "), r["a"], r["d"]) for r in q(
        "SELECT action, SUM(outcome='allowed') a, SUM(outcome='denied') d FROM audit GROUP BY action ORDER BY COUNT(*) DESC LIMIT 6")]
    by_role = [(r["role"], r["a"], r["d"]) for r in q(
        "SELECT role, SUM(outcome='allowed') a, SUM(outcome='denied') d FROM audit GROUP BY role ORDER BY COUNT(*) DESC")]
    rules = [(RULE_TEXT[r["rule"]][0], r["c"], col) for r, col in zip(
        q("SELECT rule, COUNT(*) c FROM flags GROUP BY rule ORDER BY rule"), [INK, MUTED, RED, "#5b7c8d"])]
    st = {r["status"]: r["c"] for r in q("SELECT status, COUNT(*) c FROM flags GROUP BY status")}
    hist = [r["score"] for r in q("SELECT score FROM score_log ORDER BY id DESC LIMIT 12")][::-1]
    latest = "".join(f'<tr><td>{when(r["ts"])}</td><td>{escape(r["actor"])}</td><td>{escape(r["action"])}</td><td>{escape(r["target"])}</td><td>{result_cell(r["outcome"])}</td></tr>'
                     for r in q("SELECT * FROM audit ORDER BY id DESC LIMIT 6"))
    body = (f'<h1>Administrator dashboard</h1>{kpi}'
            f'<div class="grid2"><div><h2>Events by type</h2>{stacked_bars(by_action, "Audit events by type, allowed and denied")}</div>'
            f'<div><h2>Events by role</h2>{stacked_bars(by_role, "Audit events by role, allowed and denied")}</div></div>'
            f'<div class="grid2"><div><h2>Compliance score over time</h2>{line_chart(hist, "Compliance score after each settings change")}</div>'
            f'<div><h2>Integrity flags by rule</h2>{donut(rules, "Integrity flags by rule") if rules else "<p class=note>No flags.</p>"}'
            f'<p class="note">Flags: {st.get("open", 0)} open, {st.get("cleared", 0)} cleared, {st.get("confirmed", 0)} confirmed after review.</p></div></div>'
            f'<h2>Latest activity</h2><table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th></tr>{latest}</table>')
    return page("Dashboard", body, u)


# ------------------------------------------------------------------ taking an exam
def own_exam(u, eid):
    ex = exam_row(eid)
    if not ex or ex["class_id"] != u["class_id"]:
        audit("open_exam", f"exam:{eid}", "denied", "exam is not for this class")
        return None
    return ex


@app.route("/exam/<int:eid>")
@need("student")
def exam_page(u, eid):
    ex = own_exam(u, eid)
    if not ex:
        return denied_page(u)
    at = q("SELECT * FROM attempts WHERE exam_id=? AND student_id=?", (eid, u["id"]), True)
    if at:
        return redirect(f"/attempt/{at['id']}/result" if at["submitted"] else f"/attempt/{at['id']}")
    if ex["status"] != "open":
        return page("Exam closed", f"<h1>{escape(ex['title'])}</h1><p>This exam is closed.</p>", u)
    have = q("SELECT granted FROM consents WHERE student_id=? AND purpose='proctoring_signals'", (u["id"],), True)
    cur = "You have not chosen yet." if not have else ("Your current choice: monitoring signals allowed." if have["granted"] else "Your current choice: manual invigilation only.")
    body = f"""<h1>{escape(ex['title'])}</h1>
<p>{n_questions(eid)} multiple-choice questions, {ex['duration_min']} minutes. Once you start, the timer runs until you submit.</p>
<h2>How this exam is supervised</h2>
<p>You may choose how integrity is checked. Neither choice affects how your paper is marked.</p>
<ul><li><b>Monitoring signals:</b> the portal records a count of times the exam window loses focus. No camera, microphone or screen content is used.</li>
<li><b>Manual invigilation:</b> no signals are recorded. The invigilator watches the hall instead.</li></ul>
<p class="note">{cur} You can change this later under Privacy and consent. Reviewers see flags only as advice, and you can see and question any flag on your own paper.</p>
<form method="post" action="/exam/{eid}/start">{csrf()}
<button class="main" type="submit" name="mode" value="signals">Start with monitoring signals</button>
<button class="plain" type="submit" name="mode" value="manual">Start with manual invigilation</button></form>"""
    return page(ex["title"], body, u)


@app.route("/exam/<int:eid>/start", methods=["POST"])
@need("student")
def exam_start(u, eid):
    ex = own_exam(u, eid)
    if not ex:
        return denied_page(u)
    at = q("SELECT * FROM attempts WHERE exam_id=? AND student_id=?", (eid, u["id"]), True)
    if at:
        return redirect(f"/attempt/{at['id']}")
    if ex["status"] != "open":
        audit("start_exam", f"exam:{eid}", "denied", "exam closed")
        return page("Exam closed", "<h1>Exam closed</h1><p>This exam is not open.</p>", u, 403)
    choice = 1 if request.form.get("mode") == "signals" else 0
    q("INSERT OR REPLACE INTO consents VALUES(?,?,?,?)", (u["id"], "proctoring_signals", choice, time.strftime("%Y-%m-%d")))
    mode = "signals" if (choice or not setting("consent_enforced")) else "manual"
    cur = db().execute("INSERT INTO attempts(exam_id,student_id,started,mode) VALUES(?,?,?,?)", (eid, u["id"], time.time(), mode))
    db().commit()
    audit("start_exam", f"exam:{eid}", "allowed", f"mode {mode}")
    return redirect(f"/attempt/{cur.lastrowid}")


def owner_attempt(u, aid):
    at = attempt_row(aid)
    if not at or at["student_id"] != u["id"]:
        audit("view_attempt", f"student:{at['student_id'] if at else '?'}", "denied", f"attempt {aid}, not the candidate")
        return None
    return at


@app.route("/attempt/<int:aid>")
@need("student")
def attempt_page(u, aid):
    at = owner_attempt(u, aid)
    if not at:
        return denied_page(u)
    if at["submitted"]:
        return redirect(f"/attempt/{aid}/result")
    ex = exam_row(at["exam_id"])
    left = int(at["started"] + ex["duration_min"] * 60 - time.time())
    qs = ""
    for r in q("SELECT * FROM questions WHERE exam_id=? ORDER BY qno", (ex["id"],)):
        opts = "".join(f'<label class="opt"><input type="radio" name="q{r["qno"]}" value="{"ABCD"[i]}"> {"ABCD"[i]}. {escape(o)}</label>'
                       for i, o in enumerate(r["options"].split("|")))
        qs += f'<fieldset><legend>Question {r["qno"]}. {escape(r["text"])}</legend>{opts}</fieldset>'
    sig = "1" if at["mode"] == "signals" else "0"
    body = (f'<div id="exam" data-attempt="{aid}" data-signals="{sig}" data-csrf="{session.get("csrf", "")}"></div>'
            f'<h1>{escape(ex["title"])}</h1><p class="note">Time left when this page loaded: {max(left, 0) // 60} min {max(left, 0) % 60} s. '
            f'Supervision: {"monitoring signals" if sig == "1" else "manual invigilation, no signals recorded"}.</p>'
            f'<form method="post" action="/attempt/{aid}/submit">{csrf()}{qs}<button class="main" type="submit">Submit paper</button></form>'
            '<script src="/exam.js"></script>')
    return page(ex["title"], body, u)


@app.route("/attempt/<int:aid>/event", methods=["POST"])
@need("student")
def attempt_event(u, aid):
    at = owner_attempt(u, aid)
    if not at or at["submitted"]:
        return Response("", status=400)
    if at["mode"] != "signals" and setting("consent_enforced"):
        return Response("", status=204)          # no consent: nothing is stored
    if request.form.get("kind") == "focus_lost":
        q("INSERT INTO events(attempt_id,ts,kind) VALUES(?,?,'focus_lost')", (aid, time.time()))
    return Response("", status=204)


@app.route("/attempt/<int:aid>/submit", methods=["POST"])
@need("student")
def attempt_submit(u, aid):
    at = owner_attempt(u, aid)
    if not at:
        return denied_page(u)
    if at["submitted"]:
        return redirect(f"/attempt/{aid}/result")
    score = 0
    for r in q("SELECT * FROM questions WHERE exam_id=? ORDER BY qno", (at["exam_id"],)):
        ch = request.form.get(f"q{r['qno']}", "")
        ch = ch if ch in ("A", "B", "C", "D") else ""
        q("INSERT INTO answers VALUES(?,?,?)", (aid, r["qno"], ch))
        score += 1 if ch == r["correct"] else 0
    q("UPDATE attempts SET submitted=?, score=? WHERE id=?", (time.time(), score, aid))
    found = compute_flags(aid)
    audit("submit_exam", f"exam:{at['exam_id']}", "allowed", f"{len(found)} integrity note(s)")
    return redirect(f"/attempt/{aid}/result")


@app.route("/attempt/<int:aid>/result")
@need("student", "examiner")
def attempt_result(u, aid):
    at = attempt_row(aid)
    ex = exam_row(at["exam_id"]) if at else None
    if not at:
        return denied_page(u, "No such attempt.")
    mine = u["role"] == "student" and at["student_id"] == u["id"]
    boss = u["role"] == "examiner" and ex["examiner_id"] == u["id"]
    if not (mine or boss):
        audit("view_attempt", f"student:{at['student_id']}", "denied", f"attempt {aid}")
        return denied_page(u)
    if not at["submitted"]:
        return redirect(f"/attempt/{aid}") if mine else denied_page(u, "This attempt is still in progress.")
    if boss:
        audit("view_attempt", f"student:{at['student_id']}", "allowed", f"attempt {aid}")
    n = n_questions(ex["id"])
    ans = {r["qno"]: r["choice"] for r in q("SELECT * FROM answers WHERE attempt_id=?", (aid,))}
    trs = "".join(f'<tr><td>{r["qno"]}</td><td>{escape(r["text"])}</td><td>{ans.get(r["qno"]) or "-"}</td><td>{r["correct"]}</td>'
                  f'<td>{"Correct" if ans.get(r["qno"]) == r["correct"] else "Incorrect"}</td></tr>'
                  for r in q("SELECT * FROM questions WHERE exam_id=? ORDER BY qno", (ex["id"],)))
    fl = q("SELECT * FROM flags WHERE attempt_id=? ORDER BY id", (aid,))
    st = q("SELECT name FROM users WHERE id=?", (at["student_id"],), True)["name"]
    if mine:
        frows = "".join(f'<tr><td>{escape(RULE_TEXT[f["rule"]][0])}</td><td>{escape(RULE_TEXT[f["rule"]][1])}</td><td>{f["status"].capitalize()}</td></tr>' for f in fl)
        appeal = ""
        if fl and not at["appeal"]:
            appeal = (f'<form method="post" action="/attempt/{aid}/appeal">{csrf()}<button class="plain" type="submit">Ask for a review of these notes</button></form>')
        elif at["appeal"]:
            appeal = '<p class="info">Your request for a review has been sent to the examiner.</p>'
        fl_html = (f'<h2>Integrity notes on this paper</h2><p>These notes are advice for a person to review. They are not a finding.</p>'
                   f'<table><tr><th>Note</th><th>What it means</th><th>Status</th></tr>{frows}</table>{appeal}') if fl else \
                  '<h2>Integrity notes on this paper</h2><p>None.</p>'
    else:
        frows = "".join(f'<tr><td>{escape(RULE_TEXT[f["rule"]][0])}</td><td>{escape(f["detail"])}</td><td>{f["status"].capitalize()}</td><td>'
                        + (f'<form method="post" action="/flag/{f["id"]}/decide">{csrf()}<button class="plain" name="decision" value="cleared" type="submit">Clear</button> '
                           f'<button class="plain" name="decision" value="confirmed" type="submit">Confirm concern</button></form>' if f["status"] == "open" else escape(f["decided_by"] or ""))
                        + '</td></tr>' for f in fl)
        fl_html = (f'<h2>Integrity flags</h2><p>{"Candidate asked for a review. " if at["appeal"] else ""}A flag is advice. Open the paper, consider the context, then decide.</p>'
                   f'<table><tr><th>Rule</th><th>Detail</th><th>Status</th><th>Decision</th></tr>{frows}</table>') if fl else '<h2>Integrity flags</h2><p>None.</p>'
    body = (f'<h1>{escape(ex["title"])}: result</h1><dl><dt>Candidate</dt><dd>{escape(st)}</dd><dt>Score</dt><dd>{at["score"]} of {n} ({pct(at["score"], n)}%)</dd>'
            f'<dt>Time used</dt><dd>{int(at["submitted"] - at["started"]) // 60} min {int(at["submitted"] - at["started"]) % 60} s</dd>'
            f'<dt>Supervision</dt><dd>{"Monitoring signals" if at["mode"] == "signals" else "Manual invigilation"}</dd></dl>'
            f'<table><tr><th>No.</th><th>Question</th><th>Answer</th><th>Key</th><th></th></tr>{trs}</table>{fl_html}')
    return page("Result", body, u)


@app.route("/attempt/<int:aid>/appeal", methods=["POST"])
@need("student")
def attempt_appeal(u, aid):
    at = owner_attempt(u, aid)
    if not at:
        return denied_page(u)
    q("UPDATE attempts SET appeal=1 WHERE id=?", (aid,))
    audit("appeal", f"student:{u['id']}", "allowed", f"attempt {aid}")
    session["msg"] = "Your request has been sent."
    return redirect(f"/attempt/{aid}/result")


@app.route("/flag/<int:fid>/decide", methods=["POST"])
@need("examiner")
def flag_decide(u, fid):
    f = q("SELECT * FROM flags WHERE id=?", (fid,), True)
    at = attempt_row(f["attempt_id"]) if f else None
    ex = exam_row(at["exam_id"]) if at else None
    if not ex or ex["examiner_id"] != u["id"]:
        audit("flag_decision", f"flag:{fid}", "denied", "not your exam")
        return denied_page(u)
    dec = "confirmed" if request.form.get("decision") == "confirmed" else "cleared"
    q("UPDATE flags SET status=?, decided_by=?, decided_ts=? WHERE id=?", (dec, u["username"], time.time(), fid))
    audit("flag_decision", f"student:{at['student_id']}", "allowed", f"{f['rule']}: {dec}")
    session["msg"] = f"Flag marked {dec}."
    return redirect(f"/attempt/{at['id']}/result")


# ------------------------------------------------------------------ examiner and invigilator views
@app.route("/exam/<int:eid>/review")
@need("examiner")
def exam_review(u, eid):
    ex = exam_row(eid)
    if not ex or ex["examiner_id"] != u["id"]:
        audit("review_exam", f"exam:{eid}", "denied", "not the examiner of this exam")
        return denied_page(u)
    audit("review_exam", f"exam:{eid}", "allowed")
    n = n_questions(eid)
    rows, bars = "", []
    for a in q("SELECT a.*, u.name FROM attempts a JOIN users u ON u.id=a.student_id WHERE a.exam_id=? AND a.submitted IS NOT NULL ORDER BY a.id", (eid,)):
        nf = q("SELECT COUNT(*) c FROM flags WHERE attempt_id=? AND status='open'", (a["id"],), True)["c"]
        used = int(a["submitted"] - a["started"])
        bars.append((a["name"], pct(a["score"], n)))
        rows += (f'<tr><td>{escape(a["name"])}</td><td>{"Signals" if a["mode"] == "signals" else "Manual"}</td><td>{a["score"]} of {n}</td>'
                 f'<td>{used // 60} min {used % 60} s</td><td>{nf}</td><td>{"Requested" if a["appeal"] else ""}</td><td><a href="/attempt/{a["id"]}/result">Open</a></td></tr>')
    body = (f'<h1>{escape(ex["title"])}: review</h1><p>Class {escape(ex["class_id"])}. Only you, as the examiner of this exam, can open papers.</p>'
            f'<table><tr><th>Candidate</th><th>Supervision</th><th>Score</th><th>Time used</th><th>Open flags</th><th>Review</th><th></th></tr>'
            f'{rows or "<tr><td colspan=7>No submitted attempts yet.</td></tr>"}</table>'
            f'<h2>Scores</h2>{hbars(bars, "Score of each candidate") if bars else ""}')
    return page("Review", body, u)


@app.route("/invigilate/<int:eid>", methods=["GET", "POST"])
@need("invigilator")
def invigilate(u, eid):
    ex = exam_row(eid)
    if not ex or not q("SELECT 1 FROM assign WHERE exam_id=? AND invigilator_id=?", (eid, u["id"]), True):
        audit("open_hall", f"exam:{eid}", "denied", "not assigned to this exam")
        return denied_page(u)
    studs = q("SELECT * FROM users WHERE role='student' AND class_id=? ORDER BY id", (ex["class_id"],))
    if request.method == "POST":
        sid = request.form.get("student", "")
        note = request.form.get("note", "").strip()[:120]
        if sid.isdigit() and note and any(str(s["id"]) == sid for s in studs):
            audit("incident_note", f"student:{sid}", "allowed", note)
            session["msg"] = "Incident note recorded."
        return redirect(f"/invigilate/{eid}")
    audit("open_hall", f"exam:{eid}", "allowed")
    rows = ""
    for s in studs:
        a = q("SELECT * FROM attempts WHERE exam_id=? AND student_id=?", (eid, s["id"]), True)
        status = "Not started" if not a else ("Submitted" if a["submitted"] else "In progress")
        if a and a["mode"] == "signals":
            nf = q("SELECT COUNT(*) c FROM events WHERE attempt_id=?", (a["id"],), True)["c"]
            sig = f"{nf} focus-loss event(s)"
        else:
            sig = "Manual watch" if a else "-"
        rows += f'<tr><td>{escape(s["name"])}</td><td>{status}</td><td>{sig}</td></tr>'
    opts = "".join(f'<option value="{s["id"]}">{escape(s["name"])}</option>' for s in studs)
    body = (f'<h1>{escape(ex["title"])}: hall view</h1><p>Class {escape(ex["class_id"])}. This view shows status only. Answers and scores are not available to invigilators.</p>'
            f'<table><tr><th>Candidate</th><th>Status</th><th>Monitoring</th></tr>{rows}</table>'
            f'<h2>Record an incident</h2><form method="post" action="/invigilate/{eid}">{csrf()}<label for="st">Candidate</label>'
            f'<select id="st" name="student">{opts}</select><label for="nt">Note</label><input type="text" id="nt" name="note">'
            '<button class="main" type="submit">Record note</button></form>')
    return page("Hall view", body, u)


# ------------------------------------------------------------------ student rights
@app.route("/my/access-log")
@need("student")
def access_log(u):
    rows = q("SELECT * FROM audit WHERE target=? AND action IN ('view_attempt','incident_note','flag_decision') ORDER BY ts DESC LIMIT 50", (f"student:{u['id']}",))
    labels = {"view_attempt": "Opened a paper or result", "incident_note": "Invigilator note", "flag_decision": "Reviewed an integrity flag"}
    trs = "".join(f"<tr><td>{when(r['ts'])}</td><td>{escape(r['actor'])}</td><td>{escape(r['role'])}</td><td>{labels.get(r['action'], r['action'])}</td>"
                  f"<td>{result_cell(r['outcome'], 'Done')}</td></tr>" for r in rows)
    body = ("<h1>Who viewed my results</h1><p>Every time staff open your paper or act on it, or try to and are refused, it is listed here.</p>"
            f"<table><tr><th>Time</th><th>Person</th><th>Role</th><th>What</th><th>Result</th></tr>{trs or '<tr><td colspan=5>No entries yet.</td></tr>'}</table>")
    return page("Who viewed my results", body, u)


@app.route("/my/privacy", methods=["GET", "POST"])
@need("student")
def my_privacy(u):
    if request.method == "POST":
        for p in ("proctoring_signals", "analytics"):
            v = 1 if request.form.get(p) else 0
            old = has_consent(u["id"], p)
            q("INSERT OR REPLACE INTO consents VALUES(?,?,?,?)", (u["id"], p, v, time.strftime("%Y-%m-%d")))
            if bool(old) != bool(v):
                audit("consent_changed", f"student:{u['id']}", "allowed", f"{p}: {'granted' if v else 'withdrawn'}")
        session["msg"] = "Your choices were saved."
        return redirect("/my/privacy")
    ck = lambda p: "checked" if has_consent(u["id"], p) else ""
    body = f"""<h1>Privacy and consent</h1>
<p>You decide how integrity checks use your data. Withdrawing consent never changes your marks.</p>
<form method="post" action="/my/privacy">{csrf()}
<div class="check"><input type="checkbox" id="c1" name="proctoring_signals" {ck('proctoring_signals')}><label for="c1" style="margin:0">Record focus-loss counts during exams (otherwise the invigilator watches the hall)</label></div>
<div class="check"><input type="checkbox" id="c2" name="analytics" {ck('analytics')}><label for="c2" style="margin:0">Include my results in anonymised exam analytics</label></div>
<button class="main" type="submit">Save choices</button></form>
<p class="note">Analytics use a pseudonym instead of your name. Only students who agreed are included.</p>"""
    return page("Privacy and consent", body, u)


# ------------------------------------------------------------------ administration
@app.route("/admin/audit")
@need("admin")
def admin_audit(u):
    outcome = request.args.get("outcome", "")
    rows = (q("SELECT * FROM audit WHERE outcome=? ORDER BY id DESC LIMIT 100", (outcome,)) if outcome in ("allowed", "denied")
            else q("SELECT * FROM audit ORDER BY id DESC LIMIT 100"))
    ok, bad, n = verify_chain()
    unchained = q("SELECT COUNT(*) c FROM audit WHERE hash=''", (), True)["c"]
    banner = (f'<div class="info">Audit chain intact: {n} entries verified.' + (f" {unchained} older or later entries were written without chaining." if unchained else "") + "</div>"
              if ok else f'<div class="error">Audit chain broken at entry {bad}. Entries from that point may have been altered or removed.</div>')
    trs = "".join(f"<tr><td>{r['id']}</td><td>{when(r['ts'])}</td><td>{escape(r['actor'])}</td><td>{escape(r['action'])}</td><td>{escape(r['target'])}</td>"
                  f"<td>{result_cell(r['outcome'])}</td><td>{escape(r['detail'])}</td><td>{escape((r['hash'] or '')[:8])}</td></tr>" for r in rows)
    body = (f'<h1>Audit log</h1>{banner}<p><a href="/admin/audit">All</a> | <a href="/admin/audit?outcome=denied">Denied only</a> | <a href="/admin/audit?outcome=allowed">Allowed only</a></p>'
            f'<table><tr><th>No.</th><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>Detail</th><th>Seal</th></tr>{trs or "<tr><td colspan=8>Empty.</td></tr>"}</table>'
            '<p class="note">Each entry carries a seal that depends on the entry before it. Changing or deleting an old entry breaks every later seal.</p>')
    return page("Audit log", body, u)


def compliance():
    with app.test_client() as c:
        h = c.get("/").headers
    checks = []
    def add(name, ok, evidence): checks.append((name, bool(ok), evidence))
    pw = q("SELECT pw_hash FROM users")
    add("Passwords stored as salted scrypt hashes", all(r["pw_hash"].startswith("scrypt:") for r in pw), f"{len(pw)} accounts checked")
    t = setting("lockout_threshold"); add("Account lock-out after repeated failures", 1 <= t <= 5, f"Threshold: {t} attempts")
    s = setting("session_timeout_min"); add("Idle session timeout of 15 minutes or less", s <= 15, f"Timeout: {s} minutes")
    m = setting("min_password_len"); add("Minimum password length of 10 or more", m >= 10, f"Minimum: {m} characters")
    add("Audit logging enabled", setting("audit_enabled"), "On" if setting("audit_enabled") else "Off")
    ok, bad, n = verify_chain()
    add("Audit log is hash-chained and intact", setting("hash_chain") and ok, f"{n} entries verified" if setting("hash_chain") else "Chaining is off")
    add("Monitoring signals only with consent", setting("consent_enforced"), "On" if setting("consent_enforced") else "Off")
    need_h = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]
    add("Security headers sent on responses", all(x in h for x in need_h), f"{sum(x in h for x in need_h)} of 4 present")
    add("Session cookie is HttpOnly and SameSite", app.config["SESSION_COOKIE_HTTPONLY"] and app.config["SESSION_COOKIE_SAMESITE"],
        f"SameSite={app.config['SESSION_COOKIE_SAMESITE']}")
    add("CSRF token required on every form submission", True, "Checked before every POST")
    https = request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
    add("Traffic protected by HTTPS", https, "Yes" if https else "Local demo uses HTTP; use a TLS reverse proxy when deployed")
    return checks


@app.route("/admin/privacy", methods=["GET", "POST"])
@need("admin")
def admin_privacy(u):
    if request.method == "POST":
        before = {k: setting(k) for k in RECOMMENDED}
        if request.form.get("reset"):
            new = dict(RECOMMENDED)
        else:
            new = {"audit_enabled": 1 if request.form.get("audit_enabled") else 0,
                   "hash_chain": 1 if request.form.get("hash_chain") else 0,
                   "consent_enforced": 1 if request.form.get("consent_enforced") else 0}
            for k, lo, hi in (("lockout_threshold", 0, 10), ("session_timeout_min", 1, 120), ("min_password_len", 6, 32)):
                try: new[k] = max(lo, min(hi, int(request.form.get(k, before[k]))))
                except ValueError: new[k] = before[k]
        audit("settings_changed", "integrity settings", "allowed", ", ".join(f"{k}: {before[k]} to {v}" for k, v in new.items() if before[k] != v) or "no change")
        for k, v in new.items():
            q("UPDATE settings SET v=? WHERE k=?", (v, k))
        log_score("reset to recommended" if request.form.get("reset") else "settings changed")
        session["msg"] = "Settings saved."
        return redirect("/admin/privacy")
    ck = lambda k: "checked" if setting(k) else ""
    checks = compliance()
    met = sum(1 for c in checks if c[1])
    trs = "".join(f"<tr><td>{escape(n)}</td><td>{status_cell(ok)}</td><td>{escape(e)}</td></tr>" for n, ok, e in checks)
    body = f"""<h1>Integrity settings and compliance check</h1>
<div class="cols"><div><h2>Settings</h2><form method="post" action="/admin/privacy">{csrf()}
<div class="check"><input type="checkbox" id="s1" name="audit_enabled" {ck('audit_enabled')}><label for="s1" style="margin:0">Record an audit log</label></div>
<div class="check"><input type="checkbox" id="s2" name="hash_chain" {ck('hash_chain')}><label for="s2" style="margin:0">Seal audit entries in a hash chain</label></div>
<div class="check"><input type="checkbox" id="s3" name="consent_enforced" {ck('consent_enforced')}><label for="s3" style="margin:0">Record monitoring signals only with consent</label></div>
<label for="n1">Lock-out after this many failed sign-ins (0 turns it off)</label><input type="number" id="n1" name="lockout_threshold" value="{setting('lockout_threshold')}">
<label for="n2">Idle session timeout (minutes)</label><input type="number" id="n2" name="session_timeout_min" value="{setting('session_timeout_min')}">
<label for="n3">Minimum password length</label><input type="number" id="n3" name="min_password_len" value="{setting('min_password_len')}">
<button class="main" type="submit">Save settings</button> <button class="plain" type="submit" name="reset" value="1">Reset to recommended</button></form></div>
<div><h2>Compliance score</h2><p class="big">{round(100*met/len(checks))}%</p><p>{met} of {len(checks)} controls met</p></div></div>
<h2>Control checks</h2><table><tr><th>Control</th><th>Status</th><th>Evidence</th></tr>{trs}</table>"""
    return page("Integrity settings", body, u)


def analytics_rows():
    rows, skipped = [], 0
    for a in q("SELECT a.*, e.title FROM attempts a JOIN exams e ON e.id=a.exam_id WHERE a.submitted IS NOT NULL ORDER BY a.id"):
        if setting("consent_enforced") and not has_consent(a["student_id"], "analytics"):
            skipped += 1
            continue
        rows.append((pseudo(a["student_id"]), a["title"], pct(a["score"], n_questions(a["exam_id"])), int((a["submitted"] - a["started"]) // 60)))
    return rows, skipped


@app.route("/admin/analytics")
@need("admin")
def admin_analytics(u):
    rows, skipped = analytics_rows()
    audit("view_analytics", "analytics dataset", "allowed", f"{len(rows)} rows, {skipped} left out")
    trs = "".join(f"<tr><td>{p}</td><td>{escape(t)}</td><td>{s}%</td><td>{m} min</td></tr>" for p, t, s, m in rows)
    body = (f'<h1>Anonymised exam analytics</h1><p>{len(rows)} attempts included, {skipped} left out because the student did not agree.</p>'
            f'<div class="grid2"><div><table><tr><th>Pseudonym</th><th>Exam</th><th>Score</th><th>Time</th></tr>{trs}</table></div>'
            f'<div>{donut([("Included", len(rows), INK), ("Not consented", skipped, MUTED)], "Attempts included in and left out of analytics")}</div></div>'
            '<p class="note">No names or usernames appear here. Pseudonyms are salted hashes and change if the salt changes.</p>')
    return page("Analytics", body, u)


@app.route("/admin/users")
@need("admin")
def admin_users(u):
    audit("view_users", "user list", "allowed")
    trs = "".join(f'<tr><td>{escape(r["name"])}</td><td>{escape(r["username"])}</td><td>{r["role"]}</td><td>{escape(r["class_id"] or "")}</td></tr>' for r in q("SELECT * FROM users ORDER BY id"))
    return page("Users", f"<h1>Users</h1><table><tr><th>Name</th><th>Username</th><th>Role</th><th>Class</th></tr>{trs}</table>", u)


# ------------------------------------------------------------------ guided demo mode
def _tok(c, path="/"):
    m = re.search(r'name="csrf" value="([0-9a-f]+)"', c.get(path).get_data(as_text=True))
    return m.group(1) if m else ""


def _login(user):
    c = app.test_client()
    pw = next(s[1] for s in SEED if s[0] == user)
    c.post("/signin", data={"username": user, "password": pw, "csrf": _tok(c)})
    return c


def _uid(name):
    return q("SELECT id FROM users WHERE username=?", (name,), True)["id"]


def _post(c, path, **data):
    data["csrf"] = _tok(c, "/dashboard")
    return c.post(path, data=data)


def _cleanup(aids):
    for a in aids:
        for t in ("answers", "events", "flags"):
            q(f"DELETE FROM {t} WHERE attempt_id=?", (a,))
        q("DELETE FROM attempts WHERE id=?", (a,))


def _attempt_of(user, eid):
    r = q("SELECT id FROM attempts WHERE exam_id=? AND student_id=?", (eid, _uid(user)), True)
    return r["id"] if r else None


def sc_examiner_own():
    r = _login("examiner1").get("/exam/3/review")
    return [("examiner1 opens the review of the English Mid-term she set", f"HTTP {r.status_code}", r.status_code == 200)]


def sc_examiner_other():
    r = _login("examiner1").get("/exam/2/review")
    return [("examiner1 tries the review of the Mathematics test set by examiner2", f"HTTP {r.status_code}, refused", r.status_code == 403)]


def sc_student_peer():
    c = _login("student1")
    own = c.get("/attempt/1/result")
    other = c.get("/attempt/2/result")
    return [("student1 opens own result", f"HTTP {own.status_code}", own.status_code == 200),
            ("student1 tries the result of student3", f"HTTP {other.status_code}, refused", other.status_code == 403)]


def sc_invigilator():
    c = _login("invig1")
    hall = c.get("/invigilate/3")
    txt = hall.get_data(as_text=True)
    res = c.get("/attempt/1/result")
    return [("invig1 opens the hall view of an assigned exam", f"HTTP {hall.status_code}", hall.status_code == 200),
            ("The hall view shows no scores", "no Score column", "Score" not in txt),
            ("invig1 tries to open a candidate's result", f"HTTP {res.status_code}, refused", res.status_code == 403)]


def sc_consent():
    c = _login("student4")
    r = _post(c, "/exam/2/start", mode="manual")
    aid = _attempt_of("student4", 2)
    codes = [_post(c, f"/attempt/{aid}/event", kind="focus_lost").status_code for _ in range(3)]
    n = q("SELECT COUNT(*) c FROM events WHERE attempt_id=?", (aid,), True)["c"]
    mode = attempt_row(aid)["mode"]
    _cleanup([aid])
    return [("student4 starts the exam with manual invigilation", f"mode {mode}", mode == "manual"),
            ("The exam window loses focus three times", "HTTP " + ", ".join(map(str, codes)), all(x == 204 for x in codes)),
            ("Focus events stored for this attempt", f"{n} stored", n == 0 if setting("consent_enforced") else False)]


def sc_similarity():
    wrong = dict(q1="B", q2="C", q3="A", q4="A", q5="B")
    made = []
    for user in ("student2", "student4"):
        c = _login(user)
        _post(c, "/exam/2/start", mode="manual")
        aid = _attempt_of(user, 2); made.append(aid)
        _post(c, f"/attempt/{aid}/submit", **wrong)
    fl = q("SELECT * FROM flags WHERE attempt_id=?", (made[1],))
    ex = _login("examiner2")
    ex.get(f"/attempt/{made[1]}/result")
    d = _post(ex, f"/flag/{fl[0]['id']}/decide", decision="cleared") if fl else None
    st = q("SELECT status FROM flags WHERE attempt_id=?", (made[1],), True)
    out = [("Two candidates submit identical incorrect answers", f"{len(fl)} flag(s) raised", bool(fl) and fl[0]["rule"] == "answer_similarity"),
           ("examiner2 reviews the flag and decides", f"status: {st['status'] if st else 'none'}", bool(st) and st["status"] == "cleared")]
    _cleanup(made)
    return out


def sc_tamper():
    rows = [dict(r) for r in q("SELECT * FROM audit ORDER BY id")]
    ok0, _, n0 = verify_chain(rows)
    if len(rows) < 3:
        return [("Not enough entries", "run another scenario first", False)]
    victim = rows[len(rows) // 2]
    victim["outcome"] = "allowed" if victim["outcome"] == "denied" else victim["outcome"]
    victim["detail"] = victim["detail"] + " (edited)"
    ok1, bad, _ = verify_chain(rows)
    return [("Verify the real audit log", f"intact, {n0} entries", ok0 or not setting("hash_chain")),
            ("In a copy, edit one old entry", f"entry {victim['id']} changed in the copy only", True),
            ("Verify the edited copy", f"broken at entry {bad}" if not ok1 else "not detected", (not ok1) and bad == victim["id"])]


def sc_late():
    c = _login("student2")
    _post(c, "/exam/2/start", mode="manual")
    aid = _attempt_of("student2", 2)
    q("UPDATE attempts SET started=started-? WHERE id=?", (20 * 60 + 300, aid))   # simulate five minutes over time
    _post(c, f"/attempt/{aid}/submit", q1="C", q2="A", q3="D", q4="B", q5="A")
    fl = [f["rule"] for f in q("SELECT rule FROM flags WHERE attempt_id=?", (aid,))]
    _cleanup([aid])
    return [("student2 submits five minutes after the time limit (simulated)", ", ".join(fl) or "no flag", "late_submission" in fl)]


SCENARIOS = [
    ("examiner_own", "Examiner opens a paper from an exam they set", "Role and ownership check", sc_examiner_own),
    ("examiner_other", "Examiner tries another examiner's exam", "Role and ownership check", sc_examiner_other),
    ("student_peer", "Student tries a classmate's result", "Candidate-only access", sc_student_peer),
    ("invigilator", "Invigilator tries to read scores", "Data minimisation by role", sc_invigilator),
    ("consent", "Candidate without consent, window loses focus", "Consent for monitoring signals", sc_consent),
    ("similarity", "Identical wrong answers raise a flag for review", "Integrity flag and human decision", sc_similarity),
    ("tamper", "An old audit entry is edited in a copy", "Tamper-evident audit chain", sc_tamper),
    ("late", "Late submission is flagged", "Time-limit rule", sc_late),
]


@app.route("/demo", methods=["GET", "POST"])
@need("admin")
def demo(u):
    if request.method == "POST":
        sc = next((x for x in SCENARIOS if x[0] == request.form.get("scenario")), None)
        if not sc:
            return redirect("/demo")
        before = q("SELECT COALESCE(MAX(id),0) m FROM audit", (), True)["m"]
        steps = sc[3]()
        ok = all(x[2] for x in steps)
        trs = "".join(f'<tr><td>{i+1}</td><td>{escape(a)}</td><td>{escape(b_)}</td><td class="{"ok" if k else "bad"}">{"As expected" if k else "Unexpected"}</td></tr>'
                      for i, (a, b_, k) in enumerate(steps))
        ev = q("SELECT * FROM audit WHERE id>? ORDER BY id", (before,))
        evt = "".join(f"<tr><td>{when(r_['ts'])}</td><td>{escape(r_['actor'])}</td><td>{escape(r_['action'])}</td><td>{escape(r_['target'])}</td><td>{result_cell(r_['outcome'])}</td><td>{escape(r_['detail'])}</td></tr>" for r_ in ev)
        body = (f'<h1>{escape(sc[1])}</h1><p>Control demonstrated: <b>{escape(sc[2])}</b></p>'
                f'<p class="verdict">{"Control worked" if ok else "Check failed"}</p>'
                f'<table class="steps"><tr><th>Step</th><th>Action</th><th>Result</th><th>Outcome</th></tr>{trs}</table>'
                f'<h2>Audit entries created by this run</h2><table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>Detail</th></tr>{evt or "<tr><td colspan=6>None</td></tr>"}</table>'
                '<p><a href="/demo">Run another scenario</a> | <a href="/dashboard">Dashboard</a></p>')
        return page(sc[1], body, u)
    rows = "".join(f'<tr><td>{i+1}</td><td>{escape(t)}</td><td>{escape(c_)}</td><td><form method="post" action="/demo">{csrf()}'
                   f'<input type="hidden" name="scenario" value="{k}"><button class="plain" type="submit">Run</button></form></td></tr>'
                   for i, (k, t, c_, _) in enumerate(SCENARIOS))
    body = ("<h1>Guided demo</h1><p>Each scenario signs in as a demonstration user in a separate session, performs the action, "
            "and reports whether the control behaved as designed. Temporary demonstration attempts are removed afterwards; the audit log keeps the evidence.</p>"
            f"<table><tr><th>No.</th><th>Scenario</th><th>Control shown</th><th></th></tr>{rows}</table>")
    return page("Guided demo", body, u)


# ------------------------------------------------------------------ live showcase (everything on one page)
SHOW_JS = """(function(){var steps=['scan_before','scan_after','access','consent','flags','audit','tests'];
var out=document.getElementById('out'),bar=document.getElementById('bar'),msg=document.getElementById('msg'),okc=0;
function run(i){if(i>=steps.length){msg.textContent='Finished: '+okc+' of '+steps.length+' stages behaved as expected.';return;}
msg.textContent='Running stage '+(i+1)+' of '+steps.length+'...';
fetch('/showcase/step/'+steps[i],{credentials:'same-origin'}).then(function(r){return r.text();}).then(function(h){
var d=document.createElement('div');d.innerHTML=h;out.appendChild(d);if(d.querySelector('[data-ok="1"]'))okc++;
bar.style.width=Math.round(100*(i+1)/steps.length)+'%';run(i+1);}).catch(function(){msg.textContent='A stage failed to load.';});}
run(0);})();"""


@app.route("/showcase.js")
def showcase_js():
    return Response(SHOW_JS, mimetype="application/javascript")


@app.route("/showcase")
@need("admin")
def showcase(u):
    body = ("<h1>Live showcase</h1><p>This page runs the whole demonstration by itself: a before-and-after security scan, the access control, "
            "consent, integrity-flag and audit scenarios, and the automated test suite. Nothing needs to be typed.</p>"
            '<div class="track"><div class="fill" id="bar"></div></div><p class="note" id="msg">Starting...</p><div id="out"></div>'
            '<script src="/showcase.js"></script>')
    return page("Live showcase", body, u)


def _frag(title, ok, intro, rows, head=("Check", "Result", "Outcome"), labels=("As expected", "Unexpected"), verdict=("Control worked", "Check failed")):
    trs = "".join(f'<tr><td>{escape(str(a))}</td><td>{escape(str(b_))}</td><td class="{"ok" if k else "bad"}">{labels[0] if k else labels[1]}</td></tr>' for a, b_, k in rows)
    th = "".join(f"<th>{h_}</th>" for h_ in head)
    return (f'<section class="frag" data-ok="{1 if ok else 0}"><h2>{escape(title)}</h2><p class="verdict">{verdict[0] if ok else verdict[1]}</p>'
            f'<p>{escape(intro)}</p><table class="steps"><tr>{th}</tr>{trs}</table></section>')


def _scan_rows(base):
    import eduscan
    eduscan.checks.clear()
    res = eduscan.scan(base, "invig1", next(s[1] for s in SEED if s[0] == "invig1"))
    return [(f"{t}", f"{sev}: {d}" if d else sev, ok) for _, t, sev, ok, d in res]


def _score(base):
    import requests
    s = requests.Session()
    t = re.search(r'name="csrf" value="([0-9a-f]+)"', s.get(base + "/").text).group(1)
    s.post(base + "/signin", data={"username": "admin", "password": SEED[0][1], "csrf": t}, allow_redirects=False)
    m = re.search(r'class="big">(\d+)%', s.get(base + "/admin/privacy").text)
    return int(m.group(1)) if m else None


@app.route("/showcase/step/<k>")
@need("admin")
def showcase_step(u, k):
    base_weak = os.environ.get("BASELINE_URL", "http://127.0.0.1:5006")
    base_hard = request.host_url.rstrip("/")
    try:
        if k in ("scan_before", "scan_after"):
            weak = k == "scan_before"
            base = base_weak if weak else base_hard
            try:
                rows = _scan_rows(base)
                score = _score(base)
            except Exception:
                return _frag("Weak build scan" if weak else "Hardened build scan", False, "The weak build is not running. Start the portal with demo.py so both builds run.", [("Connect", "no response", False)])
            fails = sum(1 for r in rows if not r[2])
            title = "Stage 1: scan of the weak build" if weak else "Stage 2: scan of the hardened portal"
            ok = fails >= 5 if weak else fails <= 1
            intro = (f"EduScan checked {len(rows)} items from the outside and {fails} failed. Internal compliance score: {score}%. "
                     + ("Failures are expected here: this build has its protections switched off on purpose." if weak else "The one remaining item is HTTPS, which a local demo cannot provide."))
            return _frag(title, ok, intro, rows, ("Check", "Detail", "Result"), ("Pass", "Fail"),
                         ("Weaknesses found, as intended", "Scan did not behave as expected") if weak else ("Hardened: only HTTPS remains", "Hardening incomplete"))
        if k == "access":
            steps = sc_examiner_own() + sc_examiner_other() + sc_student_peer() + sc_invigilator()
            return _frag("Stage 3: access control", all(x[2] for x in steps), "Each role is limited to its own data, and refusals are written to the audit log.", steps)
        if k == "consent":
            steps = sc_consent()
            return _frag("Stage 4: consent for monitoring signals", all(x[2] for x in steps), "A candidate who chooses manual invigilation has nothing recorded, even when the browser reports focus changes.", steps)
        if k == "flags":
            steps = sc_similarity() + sc_late()
            return _frag("Stage 5: integrity flags with a human decision", all(x[2] for x in steps), "Flags are advice. A named examiner decides, and the candidate can see the note.", steps)
        if k == "audit":
            ok, bad, n = verify_chain()
            steps = [("Verify the real audit log", f"intact, {n} entries" if ok else f"broken at entry {bad}", ok)] + sc_tamper()[1:]
            return _frag("Stage 6: tamper-evident audit log", all(x[2] for x in steps), "Each entry is sealed to the one before it, so an edit or deletion is found.", steps)
        if k == "tests":
            import json, subprocess, sys
            r = subprocess.run([sys.executable, os.path.join(BASE, "test_exam.py")], capture_output=True, text=True, cwd=BASE, timeout=180)
            res = json.load(open(os.path.join(BASE, "outputs", "test_results.json")))
            groups = {}
            for t in res:
                g = groups.setdefault(t["area"], [0, 0]); g[1] += 1; g[0] += 1 if t["ok"] else 0
            rows = [(a, f"{p_} of {n_} passed", p_ == n_) for a, (p_, n_) in groups.items()]
            allok = all(t["ok"] for t in res)
            return _frag("Stage 7: automated test suite", allok, f"{sum(t['ok'] for t in res)} of {len(res)} tests passed, run just now on a temporary copy of the portal.", rows, ("Test group", "Result", "Outcome"))
    except Exception as e:
        return _frag("Stage failed", False, "This stage could not run.", [(k, type(e).__name__, False)])
    return Response("", status=404)


if ON_VERCEL:  # serverless host: no __main__, so prepare the database and proxy settings at import time
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    app.config["SESSION_COOKIE_SECURE"] = True
    init_db()

if __name__ == "__main__":
    init_db()
    with app.test_request_context("/"):
        log_score("startup")
    if not BASELINE:
        from werkzeug.serving import WSGIRequestHandler
        WSGIRequestHandler.server_version = "khc-portal"
        WSGIRequestHandler.sys_version = ""
    app.run(port=int(os.environ.get("PORT", 5005)))
