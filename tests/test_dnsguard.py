"""Unit tests for DNSGuard's pure logic. Run: python -m unittest discover -s tests"""
import json
import os
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

os.environ.setdefault("DNSGUARD_DATA", tempfile.mkdtemp(prefix="dnsguard-test-"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dnsguard  # noqa: E402
from dnslib import QTYPE, RCODE, DNSRecord  # noqa: E402


class TestDomains(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(dnsguard.normalize_domain(" Example.COM. "), "example.com")
        self.assertEqual(dnsguard.normalize_domain("https://www.example.com/path?x=1"), "www.example.com")
        self.assertEqual(dnsguard.normalize_domain("https://www.example.com/path?x=1", strip_www=True), "example.com")
        self.assertEqual(dnsguard.normalize_domain("www.example.com:443", strip_www=True), "example.com")
        # keep "www" when it is the registrable part
        self.assertEqual(dnsguard.normalize_domain("www.com", strip_www=True), "www.com")

    def test_valid(self):
        self.assertTrue(dnsguard.valid_domain("example.com"))
        self.assertTrue(dnsguard.valid_domain("a-b.sub.example.co.uk"))
        self.assertFalse(dnsguard.valid_domain("example"))
        self.assertFalse(dnsguard.valid_domain("-bad.com"))
        self.assertFalse(dnsguard.valid_domain("bad!.com"))
        self.assertFalse(dnsguard.valid_domain(""))

    def test_base_domain(self):
        self.assertEqual(dnsguard.base_domain("a.b.example.com"), "example.com")
        self.assertEqual(dnsguard.base_domain("example.com"), "example.com")
        self.assertEqual(dnsguard.base_domain("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(dnsguard.base_domain("example.co.uk"), "example.co.uk")
        self.assertEqual(dnsguard.base_domain("x.y.z.example.co.il"), "example.co.il")

    def test_local_names(self):
        for name in ("wpad", "nas", "localhost", "printer.local", "router.lan", "1.0.0.127.in-addr.arpa", "192.168.1.1"):
            self.assertTrue(dnsguard.is_local_name(name), name)
        for name in ("example.com", "www.google.com", "a.b.c.d.e.org"):
            self.assertFalse(dnsguard.is_local_name(name), name)


class TestWhitelist(unittest.TestCase):
    def test_start_page_allowed_by_default(self):
        wl = dnsguard.Whitelist(domains=dnsguard.DEFAULT_WHITELIST)
        host = dnsguard.normalize_domain(dnsguard.START_PAGE_URL)
        self.assertEqual(host, "vote.softgiginc.com")
        self.assertEqual(wl.match(host), "domain")
        self.assertEqual(wl.match("softgiginc.com"), "domain")
        self.assertEqual(wl.match("any.sub.softgiginc.com"), "domain")

    def test_domain_covers_subdomains(self):
        wl = dnsguard.Whitelist(domains=["example.com"], exact=["only.this.org"])
        self.assertEqual(wl.match("example.com"), "domain")
        self.assertEqual(wl.match("www.example.com"), "domain")
        self.assertEqual(wl.match("a.b.c.example.com."), "domain")
        self.assertIsNone(wl.match("notexample.com"))
        self.assertIsNone(wl.match("example.com.evil.net"))

    def test_exact_covers_only_that_name(self):
        wl = dnsguard.Whitelist(domains=[], exact=["only.this.org"])
        self.assertEqual(wl.match("only.this.org"), "exact")
        self.assertEqual(wl.match("ONLY.THIS.ORG"), "exact")
        self.assertIsNone(wl.match("this.org"))
        self.assertIsNone(wl.match("www.only.this.org"))


class TestPasswords(unittest.TestCase):
    def test_roundtrip(self):
        stored = dnsguard.hash_password("correct horse", iterations=1000)
        self.assertTrue(stored.startswith("pbkdf2_sha256$1000$"))
        self.assertTrue(dnsguard.verify_password("correct horse", stored))
        self.assertFalse(dnsguard.verify_password("wrong", stored))
        self.assertFalse(dnsguard.verify_password("correct horse", "garbage"))

    def test_salts_differ(self):
        self.assertNotEqual(dnsguard.hash_password("x", 1000), dnsguard.hash_password("x", 1000))

    def test_policy(self):
        self.assertIsNotNone(dnsguard.password_problem("12345"))
        self.assertIsNone(dnsguard.password_problem("123456"))

    def test_rate_limiter(self):
        rl = dnsguard.RateLimiter(limit=3, window=60)
        self.assertEqual(rl.retry_after(), 0)
        for _ in range(3):
            rl.record_failure()
        self.assertGreater(rl.retry_after(), 0)
        rl.reset()
        self.assertEqual(rl.retry_after(), 0)


class TestConfigDefaults(unittest.TestCase):
    def test_instances_do_not_share_default_lists(self):
        a = dnsguard.Config(Path(dnsguard.DATA_DIR) / f"cfg-{uuid.uuid4().hex}.json")
        b = dnsguard.Config(Path(dnsguard.DATA_DIR) / f"cfg-{uuid.uuid4().hex}.json")
        a.data["allow_exact"].append("x.example")
        self.assertNotIn("x.example", b.data["allow_exact"])
        self.assertNotIn("x.example", dnsguard.Config.DEFAULTS["allow_exact"])


class TestLogParsing(unittest.TestCase):
    def test_aggregate(self):
        text = (
            "2026-01-01 10:00:00\tads.example.com\tA\n"
            "2026-01-01 10:00:01\tads.example.com\tAAAA\n"
            "2026-01-01 10:05:00\tcdn.example.com\tA\n"
            "2026-01-01 09:00:00\tother.org\tA\n"
            "broken line\n"
            "\n"
        )
        entries = dnsguard.parse_blocked_log(text)
        self.assertEqual([e["domain"] for e in entries], ["example.com", "other.org"])
        ex = entries[0]
        self.assertEqual(ex["hits"], 3)
        self.assertEqual(ex["last_seen"], "2026-01-01 10:05:00")
        self.assertEqual(ex["last_name"], "cdn.example.com")
        self.assertEqual(ex["first_seen"], "2026-01-01 10:00:00")

    def test_trim(self):
        path = Path(dnsguard.DATA_DIR) / "trim.log"
        log = dnsguard.BlockedLog(path, max_bytes=2000)
        for i in range(400):
            log.append(f"host{i}.example.com", "A")
        log._trim()
        size = path.stat().st_size
        self.assertLessEqual(size, 2000)
        self.assertTrue(path.read_text().endswith("host399.example.com\tA\n"))


class TestResolver(unittest.TestCase):
    def setUp(self):
        uid = uuid.uuid4().hex  # time-based names collide on Windows' 15.6 ms clock
        self.cfg_path = Path(dnsguard.DATA_DIR) / f"cfg-{uid}.json"
        self.cfg = dnsguard.Config(self.cfg_path)
        self.cfg.data["allow_domains"] = ["allowed.com"]
        self.cfg.data["allow_exact"] = ["exact.site.org"]
        self.cfg.data["password"] = dnsguard.hash_password("secret1", 1000)
        self.cfg.save()
        self.log = dnsguard.BlockedLog(Path(dnsguard.DATA_DIR) / f"log-{uid}.log")
        self.forwarded = []

        def fake_forward(data, tcp=False):
            self.forwarded.append(DNSRecord.parse(data))
            reply = DNSRecord.parse(data).reply()
            reply.add_answer(dnsguard.RR(reply.q.qname, QTYPE.A, rdata=dnsguard.A("93.184.216.34"), ttl=60))
            return reply.pack()

        self.resolver = dnsguard.Resolver(self.cfg, self.log, forwarder=fake_forward)

    def query(self, name, qtype="A"):
        data = DNSRecord.question(name, qtype).pack()
        return DNSRecord.parse(self.resolver.handle(data))

    def test_blocked_a_points_to_localhost(self):
        resp = self.query("www.blocked.net")
        self.assertEqual(resp.header.rcode, RCODE.NOERROR)
        self.assertEqual(str(resp.rr[0].rdata), "127.0.0.1")
        self.assertEqual(self.forwarded, [])
        self.assertIn("www.blocked.net\tA", self.log.read_text())

    def test_blocked_aaaa_points_to_v6_localhost(self):
        resp = self.query("www.blocked.net", "AAAA")
        self.assertEqual(str(resp.rr[0].rdata), "::1")

    def test_blocked_https_record_is_empty(self):
        resp = self.query("www.blocked.net", "HTTPS")
        self.assertEqual(resp.header.rcode, RCODE.NOERROR)
        self.assertEqual(len(resp.rr), 0)

    def test_allowed_is_forwarded(self):
        resp = self.query("deep.sub.allowed.com")
        self.assertEqual(str(resp.rr[0].rdata), "93.184.216.34")
        self.assertEqual(len(self.forwarded), 1)

    def test_exact_entry(self):
        self.assertEqual(str(self.query("exact.site.org").rr[0].rdata), "93.184.216.34")
        self.assertEqual(str(self.query("www.exact.site.org").rr[0].rdata), "127.0.0.1")

    def test_local_names_forwarded_and_not_logged(self):
        self.query("printer.local")
        self.query("nas")
        self.assertEqual(len(self.forwarded), 2)
        self.assertEqual(self.log.read_text(), "")

    def test_log_only_forwards_but_logs(self):
        self.cfg.set_option("log_only", True)
        resp = self.query("tracker.example.net")
        self.assertEqual(str(resp.rr[0].rdata), "93.184.216.34")
        self.assertIn("tracker.example.net", self.log.read_text())

    def test_pause_forwards_without_logging(self):
        self.cfg.set_option("paused_until", -1)
        resp = self.query("tracker.example.net")
        self.assertEqual(str(resp.rr[0].rdata), "93.184.216.34")
        self.assertEqual(self.log.read_text(), "")
        self.cfg.set_option("paused_until", int(time.time()) - 5)  # expired pause
        self.assertEqual(str(self.query("tracker.example.net").rr[0].rdata), "127.0.0.1")

    def test_live_reload_from_disk(self):
        self.assertEqual(str(self.query("new.site.com").rr[0].rdata), "127.0.0.1")
        raw = json.loads(self.cfg_path.read_text())
        raw["allow_domains"].append("site.com")
        time.sleep(0.02)
        self.cfg_path.write_text(json.dumps(raw))
        os.utime(self.cfg_path, None)
        self.assertTrue(self.cfg.reload_if_changed())
        self.assertEqual(str(self.query("new.site.com").rr[0].rdata), "93.184.216.34")

    def test_upstream_failure_is_servfail(self):
        self.resolver.forwarder = lambda data, tcp=False: None
        resp = self.query("allowed.com")
        self.assertEqual(resp.header.rcode, RCODE.SERVFAIL)

    def test_config_add_remove(self):
        self.assertEqual(self.cfg.add_allowed("HTTPS://WWW.Shop.Example.com/x"), "shop.example.com")
        self.assertIn("shop.example.com", self.cfg.data["allow_domains"])
        with self.assertRaises(ValueError):
            self.cfg.add_allowed("not a domain")
        self.assertTrue(self.cfg.remove_allowed("shop.example.com"))
        self.assertFalse(self.cfg.remove_allowed("shop.example.com"))
        # exact entries keep "www." so "www.x.com only" really means that host
        self.assertEqual(self.cfg.add_allowed("www.x-site.com", exact=True), "www.x-site.com")
        self.assertEqual(self.cfg.whitelist.match("www.x-site.com"), "exact")
        self.assertIsNone(self.cfg.whitelist.match("x-site.com"))


class TestBlockPage(unittest.TestCase):
    def test_render_escapes_and_fills(self):
        page = dnsguard.render_block_page("Www.Bad.Example.com:443", "https://www.bad.example.com/x?a=<b>")
        self.assertIn("Content filtering", page)
        self.assertIn("This website is blocked on this computer", page)
        self.assertIn("Allow <b>www.bad.example.com</b> only", page)
        self.assertIn("Allow <b>example.com</b> (and all subdomains)", page)
        self.assertIn("&lt;b&gt;", page)
        self.assertNotIn("<b>\"", page)

    def test_safe_redirect(self):
        self.assertEqual(dnsguard.safe_redirect_url("https://a.com/p", "a.com"), "https://a.com/p")
        self.assertEqual(dnsguard.safe_redirect_url("https://evil.com/p", "a.com"), "https://a.com/")
        self.assertEqual(dnsguard.safe_redirect_url("javascript:alert(1)", "a.com"), "https://a.com/")


class TestHostsMarker(unittest.TestCase):
    def test_toggle_and_remove_preserves_content(self):
        path = Path(dnsguard.DATA_DIR) / f"hosts-{uuid.uuid4().hex}"
        original = b"# Copyright (c) Microsoft Corp.\r\n#\r\n127.0.0.1 localhost\r\n\r\n10.0.0.5 printer\r\n"
        path.write_bytes(original)
        self.assertTrue(dnsguard.toggle_hosts_marker(path))
        first = path.read_bytes()
        self.assertTrue(first.startswith(original.rstrip(b"\r\n")))
        self.assertIn(dnsguard.HOSTS_MARKERS[0], first)
        self.assertNotIn(dnsguard.HOSTS_MARKERS[1], first)
        self.assertTrue(dnsguard.toggle_hosts_marker(path))
        second = path.read_bytes()
        self.assertIn(dnsguard.HOSTS_MARKERS[1], second)
        self.assertNotIn(dnsguard.HOSTS_MARKERS[0], second)
        self.assertEqual(second.count(b"DNSGuard"), 1)
        self.assertNotEqual(first, second)
        self.assertTrue(dnsguard.toggle_hosts_marker(path, remove=True))
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(dnsguard.toggle_hosts_marker(path, remove=True))  # nothing to do

    def test_missing_file_is_harmless(self):
        self.assertFalse(dnsguard.toggle_hosts_marker(Path(dnsguard.DATA_DIR) / "no-such-hosts"))

    def test_invalid_tld_is_local(self):
        self.assertTrue(dnsguard.is_local_name("dnsguard-a.invalid"))


if __name__ == "__main__":
    unittest.main()


class TestLogonTask(unittest.TestCase):
    def test_xml_runs_logon_for_all_users(self):
        xml = dnsguard.logon_task_xml()
        self.assertIn("<LogonTrigger>", xml)
        self.assertIn("<GroupId>S-1-5-32-545</GroupId>", xml)
        self.assertIn("logon</Arguments>", xml)
        self.assertNotIn("__CMD__", xml)

    def test_wallpaper_is_bundled(self):
        self.assertTrue(dnsguard.bundled_wallpaper().exists())

    def test_logon_command_parses(self):
        args = dnsguard.build_parser().parse_args(["logon", "--no-browser"])
        self.assertEqual(args.command, "logon")
        self.assertTrue(args.no_browser)
