"""EduScan 3 - black-box security and privacy checker for the Kestrel Hill examination portal.
Local use only: it refuses any target that is not 127.0.0.1 / localhost.
Usage: python eduscan.py http://127.0.0.1:5005 [invigilator_user invigilator_password]"""
import re, sys
from urllib.parse import urlparse
import requests

HDR = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]
checks = []  # (id, title, severity, passed, detail)


def add(i, title, sev, ok, detail=""):
    checks.append((i, title, sev, bool(ok), detail))


def token(s, base, path="/"):
    m = re.search(r'name="csrf" value="([0-9a-f]+)"', s.get(base + path).text)
    return m.group(1) if m else ""


def scan(base, user=None, pw=None):
    s = requests.Session()
    r = s.get(base + "/", timeout=5, allow_redirects=True)
    add("E1", "Traffic is encrypted (HTTPS)", "High", urlparse(base).scheme == "https",
        "Plain HTTP (acceptable on localhost only)" if urlparse(base).scheme == "http" else "HTTPS")
    for h in HDR:
        add("E2", f"Security header {h}", "Medium", h in r.headers, "present" if h in r.headers else "missing")
    srv = r.headers.get("Server", "")
    add("E3", "Server banner hides version", "Low", not any(ch.isdigit() for ch in srv), srv or "no banner")
    ck = [c for c in s.cookies]
    for c in ck:
        add("E4", f"Cookie {c.name} is HttpOnly", "Medium", c.has_nonstandard_attr("HttpOnly"), "")
        ss = c._rest.get("SameSite") or c._rest.get("samesite")
        add("E4", f"Cookie {c.name} has SameSite", "Medium", bool(ss), ss or "not set")
    if not ck:
        add("E4", "Session cookie flags", "Medium", False, "no cookie seen")
    # anonymous access to protected pages
    bad = []
    for p in ("/dashboard", "/admin/audit", "/exam/3/review", "/attempt/1/result", "/invigilate/3"):
        x = requests.get(base + p, timeout=5, allow_redirects=False)
        if x.status_code == 200:
            bad.append(p)
    add("E5", "Protected pages refuse anonymous visitors", "High", not bad, ", ".join(bad) or "all refused")
    # CSRF
    x = requests.post(base + "/signin", data={"username": "x", "password": "y"}, timeout=5, allow_redirects=False)
    add("E6", "Sign-in form requires a CSRF token", "Medium", x.status_code in (400, 403), f"status {x.status_code}")
    # uniform error message
    a = s.post(base + "/signin", data={"username": "student1", "password": "wrong-pass", "csrf": token(s, base)}, timeout=8)
    b = s.post(base + "/signin", data={"username": "no.such.user", "password": "wrong-pass", "csrf": token(s, base)}, timeout=8)
    msg = lambda t: re.sub(r"\s+", " ", re.search(r'class="error">(.*?)<', t, re.S).group(1)) if 'class="error"' in t else ""
    add("E7", "Same message for unknown user and wrong password", "Medium", msg(a.text) == msg(b.text), msg(a.text)[:60])
    # lock-out after repeated failures on a scan-only name
    codes = [s.post(base + "/signin", data={"username": "scan.target", "password": f"bad{i}", "csrf": token(s, base)}, timeout=8).status_code for i in range(8)]
    add("E8", "Account lock-out after repeated failures", "High", 429 in codes, "codes " + " ".join(map(str, codes)))
    # authenticated checks (optional): sign in as the invigilator
    if user:
        t = requests.Session()
        t.post(base + "/signin", data={"username": user, "password": pw, "csrf": token(t, base)}, timeout=8)
        hall = t.get(base + "/invigilate/3", allow_redirects=False)
        add("E9", "Invigilator hall view shows no scores", "High", hall.status_code == 200 and "Score" not in hall.text,
            f"status {hall.status_code}")
        res = t.get(base + "/attempt/1/result", allow_redirects=False)
        add("E10", "Invigilator cannot open a candidate's result", "High", res.status_code in (302, 401, 403), f"status {res.status_code}")
    return checks


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5005"
    if urlparse(url).hostname not in ("127.0.0.1", "localhost"):
        sys.exit("Refused: EduScan only scans local test systems.")
    u, p = (sys.argv[2], sys.argv[3]) if len(sys.argv) > 3 else (None, None)
    print(f"[*] Target: {url}")
    res = scan(url, u, p)
    for i, t, sev, ok, d in res:
        print(f"[{'PASS' if ok else 'FAIL'}] {i:3} {sev:6} {t}  --  {d}")
    f = [r for r in res if not r[3]]
    print(f"[*] Checks: {len(res)}   Passed: {len(res)-len(f)}   Failed: {len(f)}"
          f"   (High {sum(r[2]=='High' for r in f)}, Medium {sum(r[2]=='Medium' for r in f)}, Low {sum(r[2]=='Low' for r in f)})")
