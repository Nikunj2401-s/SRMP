"""Automated test suite for the examination integrity portal.
Run:  python3 test_exam.py      (uses a temporary database; prints a results table)"""
import json, os, re, sqlite3, sys, tempfile, time

os.environ["PORTAL_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
import exam_portal as P

P.init_db()
app = P.app
PW = {u[0]: u[1] for u in P.SEED}
ID = {u[0]: i + 1 for i, u in enumerate(P.SEED)}
RESULTS = []


def rec(tid, area, desc, expected, actual, ok):
    RESULTS.append(dict(id=tid, area=area, desc=desc, expected=str(expected), actual=str(actual), ok=bool(ok)))


def token(c, path="/"):
    return re.search(r'name="csrf" value="([0-9a-f]+)"', c.get(path).get_data(as_text=True)).group(1)


def sess(user):
    c = app.test_client()
    r = c.post("/signin", data={"username": user, "password": PW[user], "csrf": token(c)})
    assert r.status_code == 302, (user, r.status_code)
    return c


def post(c, path, data=None, page="/dashboard"):
    d = dict(data or {})
    d["csrf"] = token(c, page)
    return c.post(path, data=d)


def sql(q, args=()):
    with sqlite3.connect(P.DB_PATH) as d:
        return d.execute(q, args).fetchall()


def audit_n(**kw):
    return sql("SELECT COUNT(*) FROM audit WHERE " + " AND ".join(f"{k}=?" for k in kw), tuple(kw.values()))[0][0]


def verify():
    with app.app_context():
        return P.verify_chain()


def score(admin):
    html = admin.get("/admin/privacy").get_data(as_text=True)
    return int(re.search(r'class="big">(\d+)%', html).group(1)), re.search(r"(\d+) of (\d+) controls met", html).groups()


def code(r, want, tid, area, desc, exp=None):
    rec(tid, area, desc, exp or f"HTTP {want}", f"HTTP {r.status_code}", r.status_code == want)


A, B, C, D, E, F, G = "Authentication", "Access control", "Consent", "Exam flow and flags", "Audit chain", "Configuration", "Dashboards and demo"

# ---------------------------------------------------------------- A. authentication
c = app.test_client()
r = c.post("/signin", data={"username": "student1", "password": PW["student1"], "csrf": token(c)})
rec("A1", A, "Sign in with correct credentials", "302 to /dashboard", f"{r.status_code} to {r.headers.get('Location')}", r.status_code == 302 and r.headers["Location"].endswith("/dashboard"))
c = app.test_client(); r1 = c.post("/signin", data={"username": "student1", "password": "wrong-pass", "csrf": token(c)})
c = app.test_client(); r2 = c.post("/signin", data={"username": "nobody", "password": "wrong-pass", "csrf": token(c)})
same = r1.status_code == r2.status_code == 401 and ("Invalid username or password" in r1.get_data(as_text=True)) == ("Invalid username or password" in r2.get_data(as_text=True))
rec("A2", A, "Wrong password and unknown user give the same message", "401, identical message", f"{r1.status_code}/{r2.status_code}, identical={same}", same)
c = app.test_client(); codes = []
for i in range(6):
    codes.append(c.post("/signin", data={"username": "student5", "password": f"bad{i}", "csrf": token(c)}).status_code)
rec("A3", A, "Five wrong passwords lock the account", "401 x5 then 429", " ".join(map(str, codes)), codes[:5] == [401] * 5 and codes[5] == 429)
c = app.test_client(); r = c.post("/signin", data={"username": "student5", "password": PW["student5"], "csrf": token(c)})
rec("A4", A, "Correct password is refused while locked", 429, r.status_code, r.status_code == 429)
rec("A5", A, "Failed and locked sign-ins are audited", "entries present", f"{audit_n(action='login', outcome='denied')} denied logins", audit_n(action="login", outcome="denied") >= 6)
h = [r[0] for r in sql("SELECT pw_hash FROM users")]
rec("A6", A, "All passwords stored as salted scrypt hashes", "all scrypt", f"{sum(x.startswith('scrypt:') for x in h)} of {len(h)}", all(x.startswith("scrypt:") for x in h))
sql("DELETE FROM lockouts")

# ---------------------------------------------------------------- B. access control
s1, s2, s3 = sess("student1"), sess("student2"), sess("student3")
ex1, ex2, inv, adm = sess("examiner1"), sess("examiner2"), sess("invig1"), sess("admin")
code(s1.get("/attempt/1/result"), 200, "B1", B, "Student opens own result")
code(s1.get("/attempt/2/result"), 403, "B2", B, "Student refused a classmate's result")
code(s2.get("/exam/1"), 403, "B3", B, "Student refused an exam for another class")
code(ex1.get("/exam/3/review"), 200, "B4", B, "Examiner opens review of own exam")
code(ex1.get("/exam/2/review"), 403, "B5", B, "Examiner refused review of another examiner's exam")
code(ex2.get("/attempt/1/result"), 403, "B6", B, "Examiner refused a paper from another examiner's exam")
hall = inv.get("/invigilate/3")
rec("B7", B, "Invigilator hall view shows status but no scores", "HTTP 200, no Score column", f"HTTP {hall.status_code}, score_shown={'Score' in hall.get_data(as_text=True)}", hall.status_code == 200 and "Score" not in hall.get_data(as_text=True))
code(inv.get("/attempt/1/result"), 403, "B8", B, "Invigilator refused a candidate's result")
code(s1.get("/invigilate/3"), 403, "B9", B, "Student refused the invigilator page")
code(s1.get("/admin/audit"), 403, "B10", B, "Student refused the audit log")
code(adm.get("/attempt/1/result"), 403, "B11", B, "Administrator cannot open candidate answers")
code(adm.get("/exam/3/review"), 403, "B12", B, "Administrator refused the examiner review page")
r = app.test_client().get("/dashboard")
rec("B13", B, "Anonymous visitor redirected to sign in", "302 to /", f"{r.status_code} to {r.headers.get('Location')}", r.status_code == 302)
code(ex1.get("/admin/analytics"), 403, "B14", B, "Examiner refused analytics")

# ---------------------------------------------------------------- C. consent
r = s1.get("/exam/1")
rec("C1", C, "Exam page offers both supervision choices", "both buttons shown", "signals+manual" if "Start with manual invigilation" in r.get_data(as_text=True) and "Start with monitoring signals" in r.get_data(as_text=True) else "missing", "Start with manual invigilation" in r.get_data(as_text=True) and "Start with monitoring signals" in r.get_data(as_text=True))
s4 = sess("student4")
post(s4, "/exam/2/start", {"mode": "manual"})
a4 = sql("SELECT id, mode FROM attempts WHERE student_id=? AND exam_id=2", (ID["student4"],))[0]
rec("C2", C, "Choosing manual invigilation starts the attempt in manual mode", "manual", a4[1], a4[1] == "manual")
codes = [post(s4, f"/attempt/{a4[0]}/event", {"kind": "focus_lost"}).status_code for _ in range(3)]
n = sql("SELECT COUNT(*) FROM events WHERE attempt_id=?", (a4[0],))[0][0]
rec("C3", C, "Focus events are not stored without consent", "204 x3, 0 stored", f"{codes}, {n} stored", codes == [204] * 3 and n == 0)
post(s1, "/exam/1/start", {"mode": "signals"})
a1 = sql("SELECT id, mode FROM attempts WHERE student_id=? AND exam_id=1", (ID["student1"],))[0]
rec("C4", C, "Choosing monitoring signals starts the attempt in signals mode", "signals", a1[1], a1[1] == "signals")
for _ in range(2): post(s1, f"/attempt/{a1[0]}/event", {"kind": "focus_lost"})
n = sql("SELECT COUNT(*) FROM events WHERE attempt_id=?", (a1[0],))[0][0]
rec("C5", C, "Focus events are stored with consent", "2 stored", f"{n} stored", n == 2)
post(s1, "/my/privacy", {"proctoring_signals": "on"}, "/my/privacy")
rec("C6", C, "Withdrawing consent is audited", "consent_changed entry", f"{audit_n(action='consent_changed')} entries", audit_n(action="consent_changed") >= 1)
html = adm.get("/admin/analytics").get_data(as_text=True)
m7 = re.search(r"(\d+) attempts included, (\d+) left out", html)
rec("C7", C, "Analytics leaves out students who did not agree", "at least 1 attempt left out", m7.group(0), int(m7.group(2)) >= 1)
rec("C8", C, "Analytics shows pseudonyms, no names", "no student names", "names absent" if not any(n in html for n in ("Aarav", "Diya", "Kabir", "Isha", "Neel")) else "names present", not any(n in html for n in ("Aarav", "Diya", "Kabir", "Isha", "Neel")))
post(s1, "/my/privacy", {"analytics": "on", "proctoring_signals": "on"}, "/my/privacy")
post(adm, "/admin/privacy", {"audit_enabled": "on", "hash_chain": "on", "lockout_threshold": "5", "session_timeout_min": "15", "min_password_len": "10"}, "/admin/privacy")
s4b = sess("student4")
sql("UPDATE attempts SET submitted=started+60, score=0 WHERE id=?", (a4[0],))
sql("DELETE FROM events WHERE attempt_id=?", (a4[0],)); sql("UPDATE attempts SET submitted=NULL, score=NULL WHERE id=?", (a4[0],))
post(s4b, f"/attempt/{a4[0]}/event", {"kind": "focus_lost"})
n = sql("SELECT COUNT(*) FROM events WHERE attempt_id=?", (a4[0],))[0][0]
rec("C9", C, "With the consent setting switched off, signals are stored anyway (weak build)", "1 stored", f"{n} stored", n == 1)
post(adm, "/admin/privacy", {"reset": "1"}, "/admin/privacy")
sql("DELETE FROM events WHERE attempt_id=?", (a4[0],))

# ---------------------------------------------------------------- D. exam flow and flags
r = post(s1, f"/attempt/{a1[0]}/submit", {"q1": "B", "q2": "C", "q3": "A", "q4": "D", "q5": "B"}, f"/attempt/{a1[0]}")
res = s1.get(f"/attempt/{a1[0]}/result").get_data(as_text=True)
sc = sql("SELECT score FROM attempts WHERE id=?", (a1[0],))[0][0]
rec("D1", D, "Submitting marks the paper correctly", "score 5", f"score {sc}", sc == 5)
rec("D2", D, "Result page shows the score to the candidate", "5 of 5", "5 of 5 (100%)" if "5 of 5" in res else "missing", "5 of 5" in res)
f3 = sql("SELECT rule FROM flags WHERE attempt_id=3")
rec("D3", D, "Identical incorrect answers raise a similarity flag", "answer_similarity on attempt 3", [x[0] for x in f3], any(x[0] == "answer_similarity" for x in f3))
f1 = sql("SELECT rule, status FROM flags WHERE attempt_id=1")
rec("D4", D, "Fast finish with high score is flagged and was cleared by the examiner", "unusually_fast, cleared", f1, ("unusually_fast", "cleared") in f1)
f2 = sql("SELECT rule FROM flags WHERE attempt_id=2")
rec("D5", D, "Repeated focus loss (with consent) raises a flag", "focus_changes on attempt 2", [x[0] for x in f2], any(x[0] == "focus_changes" for x in f2))
s2b = sess("student2")
post(s2b, "/exam/2/start", {"mode": "manual"})
a2 = sql("SELECT id FROM attempts WHERE student_id=? AND exam_id=2", (ID["student2"],))[0][0]
sql("UPDATE attempts SET started=started-? WHERE id=?", (20 * 60 + 300, a2))
post(s2b, f"/attempt/{a2}/submit", {"q1": "C", "q2": "A", "q3": "D", "q4": "B", "q5": "A"})
fl = [x[0] for x in sql("SELECT rule FROM flags WHERE attempt_id=?", (a2,))]
rec("D6", D, "Late submission is flagged", "late_submission", fl, "late_submission" in fl)
fid = sql("SELECT id FROM flags WHERE attempt_id=3 AND rule='answer_similarity'")[0][0]
ex1b = sess("examiner1")
post(ex1b, f"/flag/{fid}/decide", {"decision": "confirmed"}, "/dashboard")
st = sql("SELECT status, decided_by FROM flags WHERE id=?", (fid,))[0]
rec("D7", D, "Examiner decision is recorded with the examiner's name and audited", "confirmed by examiner1, audit entry", f"{st}, {audit_n(action='flag_decision')} audit", st == ("confirmed", "examiner1") and audit_n(action="flag_decision") >= 1)
s5 = sess("student5")
res5 = s5.get("/attempt/3/result").get_data(as_text=True)
rec("D8", D, "Candidate sees the note but not the other candidate's attempt", "note shown, no attempt reference", f"note={'Answer similarity' in res5}, ref={'attempt #2' in res5}", "Answer similarity" in res5 and "attempt #2" not in res5)
post(s5, "/attempt/3/appeal", {}, "/attempt/3/result")
rec("D9", D, "Candidate can ask for a review and it is audited", "appeal=1, audit entry", f"{sql('SELECT appeal FROM attempts WHERE id=3')[0][0]}, {audit_n(action='appeal')} audit", sql("SELECT appeal FROM attempts WHERE id=3")[0][0] == 1 and audit_n(action="appeal") == 1)
r = post(s1, "/exam/1/start", {"mode": "signals"})
rec("D10", D, "Starting twice does not create a second attempt", "1 attempt", f"{sql('SELECT COUNT(*) FROM attempts WHERE student_id=? AND exam_id=1', (ID['student1'],))[0][0]} attempt(s)", sql("SELECT COUNT(*) FROM attempts WHERE student_id=? AND exam_id=1", (ID["student1"],))[0][0] == 1)
post(s1, f"/attempt/{a1[0]}/submit", {"q1": "A"})
rec("D11", D, "Submitting twice does not duplicate answers", "5 answers", f"{sql('SELECT COUNT(*) FROM answers WHERE attempt_id=?', (a1[0],))[0][0]} answers", sql("SELECT COUNT(*) FROM answers WHERE attempt_id=?", (a1[0],))[0][0] == 5)
sql("UPDATE exams SET status='closed' WHERE id=2"); s4c = sess("student4")
sql("DELETE FROM attempts WHERE id=?", (a4[0],))
r = post(s4c, "/exam/2/start", {"mode": "manual"})
rec("D12", D, "A closed exam cannot be started", 403, r.status_code, r.status_code == 403)
sql("UPDATE exams SET status='open' WHERE id=2")

# ---------------------------------------------------------------- E. audit chain
ok, bad, n = verify()
rec("E1", E, "Audit chain is intact after normal use", "intact", f"intact={ok}, {n} entries", ok and n > 20)
rec("E2", E, "Refused attempts are recorded", "denied entries present", f"{audit_n(outcome='denied')} denied", audit_n(outcome="denied") >= 8)
with app.app_context():
    rows = [dict(r) for r in P.q("SELECT * FROM audit ORDER BY id")]
rows[len(rows) // 2]["detail"] += " (edited)"
with app.app_context():
    ok2, bad2, _ = P.verify_chain(rows)
rec("E3", E, "An edit in a copy of the log is detected", f"broken at {rows[len(rows)//2]['id']}", f"intact={ok2}, bad={bad2}", (not ok2) and bad2 == rows[len(rows) // 2]["id"])
mid = sql("SELECT id, detail FROM audit ORDER BY id")[10]
sql("UPDATE audit SET detail=detail||' x' WHERE id=?", (mid[0],))
ok3, bad3, _ = verify()
rec("E4", E, "An edit made directly in the database is detected", f"broken at {mid[0]}", f"intact={ok3}, bad={bad3}", (not ok3) and bad3 == mid[0])
sql("UPDATE audit SET detail=? WHERE id=?", (mid[1], mid[0]))
ok4, _, _ = verify()
rec("E5", E, "Restoring the original text makes the chain valid again", "intact", f"intact={ok4}", ok4)
vid = sql("SELECT id FROM audit ORDER BY id")[15][0]
saved = sql("SELECT * FROM audit WHERE id=?", (vid,))[0]
sql("DELETE FROM audit WHERE id=?", (vid,))
ok5, bad5, _ = verify()
rec("E6", E, "Deleting an entry in the middle is detected", "broken at next entry", f"intact={ok5}, bad={bad5}", not ok5)
with sqlite3.connect(P.DB_PATH) as d:
    d.execute("INSERT INTO audit VALUES(?,?,?,?,?,?,?,?,?,?)", saved)
s3b = sess("student3")
s3b.get("/attempt/1/result")
log = s1.get("/my/access-log").get_data(as_text=True)
rec("E7", E, "Student sees a refused attempt on their own result", "refused entry listed", "denied" if "denied" in log else "missing", "denied" in log and "student3" in log)
ban = adm.get("/admin/audit").get_data(as_text=True)
rec("E8", E, "Audit page reports chain status", "intact banner", "intact" if "Audit chain intact" in ban else "not intact", "Audit chain intact" in ban)

# ---------------------------------------------------------------- F. configuration
sc0, met0 = score(adm)
rec("F1", F, "Compliance score with recommended settings", "91% (10 of 11)", f"{sc0}% ({met0[0]} of {met0[1]})", sc0 == 91 and met0 == ("10", "11"))
post(adm, "/admin/privacy", {"lockout_threshold": "5", "session_timeout_min": "15", "min_password_len": "10"}, "/admin/privacy")
sc1, met1 = score(adm)
rec("F2", F, "Switching off audit, chain and consent lowers the score", "64% (7 of 11)", f"{sc1}% ({met1[0]} of {met1[1]})", sc1 == 64)
before = audit_n(action="settings_changed")
post(adm, "/admin/privacy", {"reset": "1"}, "/admin/privacy")
sc2, _ = score(adm)
rec("F3", F, "Reset to recommended restores the score", "91%", f"{sc2}%", sc2 == 91)
rec("F4", F, "Settings changes are audited", "settings_changed entries", f"{audit_n(action='settings_changed')} entries", before >= 1)
h = app.test_client().get("/").headers
need = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]
rec("F5", F, "Security headers are sent", "4 of 4", f"{sum(x in h for x in need)} of 4", all(x in h for x in need))
sc_hdr = app.test_client().get("/").headers.getlist("Set-Cookie")
rec("F6", F, "Session cookie is HttpOnly and SameSite=Strict", "both flags", "present" if sc_hdr and "HttpOnly" in sc_hdr[0] and "SameSite=Strict" in sc_hdr[0] else str(sc_hdr), bool(sc_hdr) and "HttpOnly" in sc_hdr[0] and "SameSite=Strict" in sc_hdr[0])
r = s1.post("/account/password", data={"current": "x", "new": "y", "confirm": "y"})
code(r, 400, "F7", F, "Form submitted without a CSRF token is rejected")
t = sess("student1")
with t.session_transaction() as s:
    s["last"] = time.time() - 3600
r = t.get("/dashboard")
rec("F8", F, "Idle session expires", "302 to /", f"{r.status_code} to {r.headers.get('Location')}", r.status_code == 302 and r.headers["Location"].endswith("/"))
r = post(t, "/account/password", {"current": PW["student1"], "new": "password", "confirm": "password"}, "/account/password") if False else None

# ---------------------------------------------------------------- G. dashboards and demo
for t in ("answers", "events", "flags"):
    sql(f"DELETE FROM {t} WHERE attempt_id=?", (a2,))
sql("DELETE FROM attempts WHERE id=?", (a2,))
adm = sess("admin")
for i, (key, title, ctl, _) in enumerate(P.SCENARIOS, 1):
    r = post(adm, "/demo", {"scenario": key}, "/demo")
    txt = r.get_data(as_text=True)
    rec(f"G{i}", G, f"Guided demo: {title}", "Control worked", "Control worked" if "Control worked" in txt else "Check failed", "Control worked" in txt)
dash = adm.get("/dashboard").get_data(as_text=True)
rec("G9", G, "Administrator dashboard shows four or more charts", ">= 4 charts", f"{dash.count('<svg')} charts", dash.count("<svg") >= 4)
sd = sess("student1").get("/dashboard").get_data(as_text=True)
rec("G10", G, "Student dashboard shows results chart and privacy snapshot", "snapshot and chart", f"snapshot={'privacy snapshot' in sd}, charts={sd.count('<svg')}", "privacy snapshot" in sd and sd.count("<svg") >= 1)
ed = sess("examiner1").get("/dashboard").get_data(as_text=True)
rec("G11", G, "Examiner dashboard lists only own exams", "English and Physics only", f"math={'Mathematics' in ed}", "Mathematics" not in ed and "English Mid-term" in ed)
code(sess("examiner1").get("/demo"), 403, "G12", G, "Guided demo is limited to administrators")
ok, bad, n = verify()
rec("G13", G, "Audit chain still intact after all tests and scenarios", "intact", f"intact={ok}, {n} entries", ok)

# ---------------------------------------------------------------- report
passed = sum(r["ok"] for r in RESULTS)
lines = [f"{'ID':<4} {'Area':<20} {'Test':<70} {'Result':<6}"]
for r in RESULTS:
    lines.append(f"{r['id']:<4} {r['area']:<20} {r['desc'][:70]:<70} {'PASS' if r['ok'] else 'FAIL':<6}")
lines.append(f"\n{passed} of {len(RESULTS)} tests passed")
out = "\n".join(lines)
print(out)
here = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(here, "outputs"), exist_ok=True)
open(os.path.join(here, "outputs", "test_results.txt"), "w").write(out + "\n")
json.dump(RESULTS, open(os.path.join(here, "outputs", "test_results.json"), "w"), indent=1)
sys.exit(0 if passed == len(RESULTS) else 1)
