"""End-to-end test on high ports, no admin rights needed.

Starts `dnsguard.py run` on DNS 5353 / HTTP 18080 / HTTPS 18443 with a scratch
data folder, then checks DNS decisions, the HTTPS block page, the allow flow,
the API and live config reload over real sockets.

Run: python tests/sandbox_test.py
"""
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

from dnslib import QTYPE, DNSRecord

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(tempfile.mkdtemp(prefix="dnsguard-sandbox-"))
DNS, HTTP, HTTPS = 15353, 18080, 18443
PASSWORD = "sandbox-pass-1"
PY = sys.executable

failures = []


def check(cond, label):
    print(("  ok   " if cond else "  FAIL ") + label)
    if not cond:
        failures.append(label)


def dns_query(name, qtype="A", port=DNS, tcp=False):
    data = DNSRecord.question(name, qtype).pack()
    if tcp:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(len(data).to_bytes(2, "big") + data)
            head = s.recv(2)
            return DNSRecord.parse(s.recv(int.from_bytes(head, "big")))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        s.sendto(data, ("127.0.0.1", port))
        return DNSRecord.parse(s.recv(4096))


def answers(resp):
    return [str(rr.rdata) for rr in resp.rr]


def https_get(host, path="/", method="GET", body=None, headers=None, cafile=None):
    """TLS connection to 127.0.0.1:HTTPS with SNI=host, verified against our CA."""
    ctx = ssl.create_default_context(cafile=cafile)
    raw = socket.create_connection(("127.0.0.1", HTTPS), timeout=10)
    conn = ctx.wrap_socket(raw, server_hostname=host)
    cert = conn.getpeercert()
    req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
    for k, v in (headers or {}).items():
        req += f"{k}: {v}\r\n"
    if body is not None:
        req += f"Content-Length: {len(body)}\r\n"
    req += "\r\n"
    conn.sendall(req.encode() + (body or b""))
    chunks = []
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    conn.close()
    text = b"".join(chunks).decode("utf-8", "replace")
    head, _, page = text.partition("\r\n\r\n")
    status = int(head.split(" ")[1])
    return status, head, page, cert


def api(action, password="", **kw):
    body = json.dumps({"action": action, "password": password, **kw}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{HTTP}/__dnsguard/api", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-DNSGuard": "1"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main():
    env = dict(os.environ, DNSGUARD_DATA=str(DATA), DNSGUARD_HTTP_PORT=str(HTTP))
    proc = subprocess.Popen([PY, str(ROOT / "dnsguard.py"), "run", "--dns-port", str(DNS), "--http-port", str(HTTP),
                             "--https-port", str(HTTPS), "--no-dns", "--password", PASSWORD],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(f"data folder: {DATA}")
    try:
        deadline = time.time() + 30
        status = None
        while time.time() < deadline and proc.poll() is None:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{HTTP}/__dnsguard/api/status", timeout=2) as r:
                    status = json.loads(r.read())
                    break
            except Exception:
                time.sleep(0.3)
        if proc.poll() is not None:
            print(proc.stdout.read())
            sys.exit("service exited early")
        check(status and status.get("running"), "service started and status endpoint answers")

        print("\n[DNS]")
        r = dns_query("www.blocked-site.example")
        check(answers(r) == ["127.0.0.1"], "blocked A record resolves to 127.0.0.1")
        r = dns_query("www.blocked-site.example", "AAAA")
        check(answers(r) == ["::1"], "blocked AAAA record resolves to ::1")
        r = dns_query("www.blocked-site.example", "HTTPS")
        check(r.header.rcode == 0 and not r.rr, "blocked HTTPS record is an empty NOERROR")
        r = dns_query("www.blocked-site.example", tcp=True)
        check(answers(r) == ["127.0.0.1"], "TCP DNS works")
        r = dns_query("www.microsoft.com")
        ok = r.header.rcode == 0 and r.rr and all(a not in ("127.0.0.1", "::1") for a in answers(r))
        check(ok, f"allowed microsoft.com forwarded upstream -> {answers(r)[:2]}")
        r = dns_query("dc.local")
        check(r.header.rcode in (0, 3) and "127.0.0.1" not in answers(r), "local names are not blocked")

        print("\n[HTTPS block page]")
        cafile = str(DATA / "ca.crt")
        code, head, page, cert = https_get("www.blocked-site.example", "/some/page?x=1", cafile=cafile)
        check(code == 200, "HTTPS handshake with our CA succeeds and page is served (no cert warning)")
        sans = [v for k, v in cert.get("subjectAltName", ())]
        check("www.blocked-site.example" in sans, f"leaf certificate issued for the SNI host: {sans}")
        check("Content filtering" in page and "This website is blocked on this computer" in page, "block page text present")
        check("www.blocked-site.example" in page and "Allow <b>blocked-site.example</b>" in page, "block page shows host and base domain buttons")
        check("Connection: close" in head, "server closes connections (no keep-alive reuse after allow)")
        code2, _, page2, _ = https_get("other.blocked.test", "/", cafile=cafile)
        check(code2 == 200 and "other.blocked.test" in page2, "second host gets its own certificate")
        try:
            https_get("www.blocked-site.example", "/", cafile=None)
            check(False, "untrusted without our CA")
        except ssl.SSLError:
            check(True, "certificate is NOT trusted without our CA (expected)")
        with urllib.request.urlopen(f"http://127.0.0.1:{HTTP}/", timeout=5) as r:
            check(r.status == 200 and b"Content filtering" in r.read(), "plain HTTP block page works")

        print("\n[allow flow from the block page]")
        form = urllib.parse.urlencode({"host": "www.blocked-site.example", "url": "https://www.blocked-site.example/some/page?x=1",
                                       "mode": "exact", "password": "wrong-pass"}).encode()
        code, _, page, _ = https_get("www.blocked-site.example", "/__dnsguard/allow", "POST", form, {"Content-Type": "application/x-www-form-urlencoded"}, cafile)
        check(code == 403 and "Wrong password" in page, "wrong password rejected with message")
        form = urllib.parse.urlencode({"host": "www.blocked-site.example", "url": "https://www.blocked-site.example/some/page?x=1",
                                       "mode": "exact", "password": PASSWORD}).encode()
        code, _, page, _ = https_get("www.blocked-site.example", "/__dnsguard/allow", "POST", form, {"Content-Type": "application/x-www-form-urlencoded"}, cafile)
        check(code == 200 and "Allowed" in page and '"https://www.blocked-site.example/some/page?x=1"' in page, "correct password -> allowed page redirecting to original URL")
        r = dns_query("www.blocked-site.example")
        check("127.0.0.1" not in answers(r), f"exact name now forwarded (rcode {r.header.rcode})")
        r = dns_query("sub.www.blocked-site.example")
        check(answers(r) == ["127.0.0.1"], "exact allow does not cover subdomains")
        form = urllib.parse.urlencode({"host": "shop.other-site.example", "url": "https://shop.other-site.example/",
                                       "mode": "domain", "password": PASSWORD}).encode()
        code, _, page, _ = https_get("shop.other-site.example", "/__dnsguard/allow", "POST", form, {"Content-Type": "application/x-www-form-urlencoded"}, cafile)
        check(code == 200 and "other-site.example" in page, "domain allow accepted")
        r = dns_query("anything.other-site.example")
        check("127.0.0.1" not in answers(r), "domain allow covers subdomains")
        form = urllib.parse.urlencode({"host": "x.example", "url": "https://evil.example/", "mode": "exact", "password": PASSWORD}).encode()
        code, _, page, _ = https_get("x.example", "/__dnsguard/allow", "POST", form, {"Content-Type": "application/x-www-form-urlencoded"}, cafile)
        check('"https://x.example/"' in page, "redirect target limited to the blocked host")

        print("\n[allowed page cache handling + recently blocked]")
        with urllib.request.urlopen(f"http://127.0.0.1:{HTTP}/__dnsguard/ping", timeout=5) as r:
            check(r.headers.get("X-DNSGuard") == "ping" and b"dnsguard" in r.read(), "ping endpoint identifies the filter")
        check("__dnsguard/ping" in page and "location.replace" in page and "http-equiv" not in page, "allowed page probes the ping endpoint before redirecting (no fixed-delay refresh)")
        dns_query("login.provider.example"); dns_query("cdn.provider.example"); dns_query("x.other-thing.example")
        code, _, bp, _ = https_get("www.needs-login.example", "/", cafile=cafile)
        check('name="extra" value="provider.example"' in bp and 'value="other-thing.example"' in bp, "block page lists recently blocked domains as checkboxes")
        check('value="needs-login.example"' not in bp, "the page's own domain is not listed as an extra")
        form = urllib.parse.urlencode([("host", "www.needs-login.example"), ("url", "https://www.needs-login.example/"), ("mode", "domain"),
                                       ("password", PASSWORD), ("extra", "provider.example"), ("extra", "not a domain")]).encode()
        code, _, ap, _ = https_get("www.needs-login.example", "/__dnsguard/allow", "POST", form, {"Content-Type": "application/x-www-form-urlencoded"}, cafile)
        check(code == 200 and "127.0.0.1" not in answers(dns_query("login.provider.example")) and "127.0.0.1" not in answers(dns_query("a.needs-login.example")), "extras are allowed together with the main domain")
        check(answers(dns_query("x.other-thing.example")) == ["127.0.0.1"], "unchecked extras stay blocked")

        print("\n[API]")
        code, data = api("login", "nope")
        check(code == 403, "API rejects wrong password")
        code, data = api("login", PASSWORD)
        check(code == 200 and "www.blocked-site.example" in data["config"]["allow_exact"], "API login returns config incl. page-allowed names")
        code, data = api("blocked", PASSWORD)
        doms = [e["domain"] for e in data["entries"]]
        check("blocked-site.example" in doms, f"blocked log aggregated: {doms}")
        code, data = api("allow", PASSWORD, name="https://www.Manager-Added.example/", exact=False)
        check(code == 200 and data["name"] == "manager-added.example", "API allow normalizes pasted URL")
        check("127.0.0.1" not in answers(dns_query("a.manager-added.example")), "manager edit is live immediately")
        code, data = api("remove", PASSWORD, name="manager-added.example")
        check(answers(dns_query("a.manager-added.example")) == ["127.0.0.1"], "removal is live immediately")
        code, data = api("set_log_only", PASSWORD, value=True)
        check("127.0.0.1" not in answers(dns_query("logonly.test.example")), "log-only forwards everything")
        code, data = api("blocked", PASSWORD)
        check(any(e["domain"] == "test.example" for e in data["entries"]), "log-only still logs")
        api("set_log_only", PASSWORD, value=False)
        code, data = api("pause", PASSWORD, minutes=5)
        check(data["status"]["paused"] and "127.0.0.1" not in answers(dns_query("paused.test.example")), "pause forwards everything")
        code, data = api("resume", PASSWORD)
        check(not data["status"]["paused"] and answers(dns_query("paused.test.example")) == ["127.0.0.1"], "resume blocks again")
        code, data = api("change_password", PASSWORD, new_password="short")
        check(code == 400, "short password rejected")
        code, data = api("change_password", PASSWORD, new_password="new-pass-123")
        check(code == 200 and api("login", "new-pass-123")[0] == 200, "password change works")
        api("change_password", "new-pass-123", new_password=PASSWORD)
        code, data = api("clear_log", PASSWORD)
        check(api("blocked", PASSWORD)[1]["entries"] == [], "clear log")
        req = urllib.request.Request(f"http://127.0.0.1:{HTTP}/__dnsguard/api", data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
            check(False, "API without custom header")
        except urllib.error.HTTPError as e:
            check(e.code == 403, "API requires the X-DNSGuard header (blocks cross-site requests)")

        print("\n[rate limit]")
        for _ in range(5):
            api("login", "bad")
        code, data = api("login", PASSWORD)
        check(code == 429 and "Try again" in data["error"], "5 wrong passwords lock out even the right one")
        code, _, page, _ = https_get("www.locked.example", "/__dnsguard/allow", "POST",
                                     urllib.parse.urlencode({"host": "www.locked.example", "url": "", "mode": "exact", "password": PASSWORD}).encode(),
                                     {"Content-Type": "application/x-www-form-urlencoded"}, cafile)
        check(code == 429, "block page shares the lockout")

        print("\n[live reload of config.json edited on disk]")
        cfg_path = DATA / "private" / "config.json"
        raw = json.loads(cfg_path.read_text())
        raw["allow_domains"].append("disk-edit.example")
        time.sleep(1.1)
        cfg_path.write_text(json.dumps(raw))
        time.sleep(3)
        check("127.0.0.1" not in answers(dns_query("www.disk-edit.example")), "config.json edited on disk is picked up")

        err = DATA / "dnsguard.err"
        err_text = err.read_text() if err.exists() else ""
        check(not err_text.strip(), "no exceptions logged in dnsguard.err" + (f":\n{err_text[-1500:]}" if err_text.strip() else ""))
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
    print()
    if failures:
        print(f"{len(failures)} FAILED:\n  " + "\n  ".join(failures))
        sys.exit(1)
    print("ALL SANDBOX CHECKS PASSED")


if __name__ == "__main__":
    main()
