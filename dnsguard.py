#!/usr/bin/env python3
"""
DNSGuard - a whitelist web filter for Windows.

Everything is blocked by default. Allowed websites are forwarded to public DNS
resolvers; everything else resolves to this computer, where a local HTTP/HTTPS
server shows a block page with a password-protected "allow this website" form.

Sub-commands (run `DNSGuard.exe <command>`):
  install    install the filter on this computer (asks for admin rights)
  run        run the filter service (used by the scheduled task)
  manage     open the manager window
  uninstall  remove the filter (password required)
  pause      pause filtering for a while (password required)
  resume     resume filtering (password required)
  status     show whether the filter is running
  allow      add a website from the command line (password required)
  start      start the filter service if it is not running
  logon      set the desktop picture and open the start page (run at each sign-in)

Without a command the program installs itself if not installed, otherwise it
opens the manager window.
"""

import argparse
import base64
import copy
import ctypes
import datetime as dt
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSRecord

VERSION = "1.1.0"
APP_NAME = "DNSGuard"
TASK_NAME = "DNSGuard"
LOGON_TASK_NAME = "DNSGuard Logon"
CA_COMMON_NAME = "DNSGuard Local CA"

IS_WINDOWS = os.name == "nt"
FROZEN = getattr(sys, "frozen", False)

# ---------------------------------------------------------------------------
# Paths. DNSGUARD_DATA overrides the data folder (used for sandbox testing).
# ---------------------------------------------------------------------------
DEFAULT_DATA_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / APP_NAME
DATA_DIR = Path(os.environ.get("DNSGUARD_DATA") or DEFAULT_DATA_DIR)
SANDBOX = bool(os.environ.get("DNSGUARD_DATA"))
PRIVATE_DIR = DATA_DIR / "private"
CONFIG_FILE = PRIVATE_DIR / "config.json"
CA_KEY_FILE = PRIVATE_DIR / "ca.key"
SNAPSHOT_FILE = PRIVATE_DIR / "dns_snapshot.json"
CERT_DIR = PRIVATE_DIR / "certs"
CA_CRT_FILE = DATA_DIR / "ca.crt"
BLOCKED_LOG = DATA_DIR / "blocked.log"
ERR_LOG = DATA_DIR / "dnsguard.err"
INSTALL_MARKER = DATA_DIR / "installed.json"
INSTALLED_EXE = DATA_DIR / f"{APP_NAME}.exe"
WALLPAPER_FILE = DATA_DIR / "wallpaper.jpg"
START_MENU_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft/Windows/Start Menu/Programs" / APP_NAME

UPSTREAMS = [("1.1.1.1", 53), ("8.8.8.8", 53)]
UPSTREAM_TIMEOUT = 2.5
LOG_MAX_BYTES = 2 * 1024 * 1024
DNS_REAPPLY_SECONDS = 300
API_PREFIX = "/__dnsguard/"
API_HEADER = "X-DNSGuard"
PBKDF2_ITERATIONS = 200_000

# Opened in Edge at every sign-in. Its domain is always on the allowed list.
START_PAGE_URL = "https://vote.softgiginc.com/"
START_PAGE_DOMAIN = "softgiginc.com"

# Domains Windows itself needs so that updates, time sync, certificate
# revocation checks and the "connected to the internet" check keep working.
DEFAULT_WHITELIST = [
    "microsoft.com",
    "microsoftonline.com",
    "windowsupdate.com",
    "windows.com",
    "windows.net",
    "msftconnecttest.com",
    "msftncsi.com",
    "live.com",
    "msedge.net",
    "azureedge.net",
    "digicert.com",
    "letsencrypt.org",
    "globalsign.com",
    "sectigo.com",
    "usertrust.com",
    "pki.goog",
    START_PAGE_DOMAIN,
]

# Names that are never filtered: they belong to the local network.
LOCAL_SUFFIXES = (".local", ".localdomain", ".lan", ".home", ".home.arpa", ".arpa", ".internal", ".corp", ".localhost", ".invalid")

# Browsers (Chrome, Edge) keep their own DNS cache for a minute regardless of TTL, but they
# drop it whenever the system hosts file changes. After an allow, a marker line is toggled.
HOSTS_FILE = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
HOSTS_MARKERS = (b"127.0.0.1 dnsguard-a.invalid # DNSGuard: toggled so browsers refresh their DNS cache",
                 b"127.0.0.1 dnsguard-b.invalid # DNSGuard: toggled so browsers refresh their DNS cache")

# Two-part public suffixes so "shop.example.co.uk" aggregates to "example.co.uk".
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "co.kr", "or.kr",
    "com.br", "net.br", "org.br", "com.mx", "co.za", "org.za", "co.in", "net.in", "org.in",
    "com.cn", "net.cn", "org.cn", "com.tw", "com.hk", "com.sg", "com.my", "co.id", "com.ph",
    "co.th", "com.vn", "com.pk", "com.tr", "com.ar", "com.co", "com.pe", "com.ve",
    "co.il", "org.il", "ac.il", "net.il", "gov.il", "muni.il", "k12.il",
    "com.eg", "com.sa", "com.ua", "com.pl", "com.ru", "com.ng", "co.ke",
}

CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def now_iso():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_err(message=None, exc=None):
    """Append an exception or message to dnsguard.err. Never raises."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(ERR_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"[{now_iso()}] {message or ''}\n")
            if exc is not None:
                fh.write("".join(traceback.format_exception(exc)))
    except Exception:
        pass


_ERR_SEEN = {}
_ERR_LOCK = threading.Lock()


def log_err_dedup(key, message):
    """Log a repeating condition once, then every 100th time (keeps dnsguard.err readable)."""
    with _ERR_LOCK:
        n = _ERR_SEEN.get(key, 0) + 1
        _ERR_SEEN[key] = n
    if n == 1 or n % 100 == 0:
        log_err(f"{message} (occurrence {n})")


def has_console():
    return sys.stdout is not None and sys.stderr is not None


QUIET = False  # set by --quiet: never show message boxes (scripted use of the windowless exe)


def say(message, title=APP_NAME, error=False):
    """Print to the console, or show a message box when running without one."""
    if has_console():
        print(message)
        return
    if QUIET:
        log_err(("ERROR: " if error else "INFO: ") + message)
        return
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        (messagebox.showerror if error else messagebox.showinfo)(title, message)
        root.destroy()
    except Exception:
        log_err(message)


def is_admin():
    if not IS_WINDOWS:
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def self_command():
    """Command list that re-runs this program."""
    if FROZEN:
        return [sys.executable]
    return [sys.executable, str(Path(__file__).resolve())]


def installed_command():
    """Command (as list) that the scheduled task and shortcuts should run."""
    if FROZEN:
        return [str(INSTALLED_EXE)]
    return [sys.executable, str(Path(__file__).resolve())]


def relaunch_elevated(args):
    """Re-run this program with admin rights (UAC prompt). Returns True on launch."""
    cmd = self_command()
    exe = cmd[0]
    params = " ".join(_quote(a) for a in cmd[1:] + list(args))
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    return rc > 32


def _quote(arg):
    return subprocess.list2cmdline([arg])


def run_cmd(cmd, check=False, timeout=120):
    """Run a command without flashing a console window. Returns CompletedProcess."""
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=check,
        creationflags=CREATE_NO_WINDOW, encoding="utf-8", errors="replace",
    )


def run_ps(script, timeout=120):
    """Run a PowerShell script (encoded, so quoting is never a problem)."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return run_cmd(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
def hash_password(password, iterations=PBKDF2_ITERATIONS):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations, base64.b64encode(salt).decode(), base64.b64encode(digest).decode()
    )


def verify_password(password, stored):
    try:
        algo, iterations, salt_b64, digest_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def password_problem(password):
    """Return a reason the password is unacceptable, or None."""
    if password is None or len(password) < 6:
        return "The password must be at least 6 characters long."
    return None


class RateLimiter:
    """Allow at most `limit` failed attempts per `window` seconds."""

    def __init__(self, limit=5, window=300):
        self.limit = limit
        self.window = window
        self.failures = deque()
        self.lock = threading.Lock()

    def _prune(self, now):
        while self.failures and now - self.failures[0] > self.window:
            self.failures.popleft()

    def retry_after(self):
        """Seconds to wait before another attempt is accepted (0 = allowed)."""
        with self.lock:
            now = time.monotonic()
            self._prune(now)
            if len(self.failures) < self.limit:
                return 0
            return int(self.window - (now - self.failures[0])) + 1

    def record_failure(self):
        with self.lock:
            self.failures.append(time.monotonic())

    def reset(self):
        with self.lock:
            self.failures.clear()


# ---------------------------------------------------------------------------
# Domain names
# ---------------------------------------------------------------------------
def normalize_domain(name, strip_www=False):
    """Lower-case, strip URL parts; optionally drop a leading 'www.' (for domain-wide entries)."""
    name = (name or "").strip().lower().rstrip(".")
    name = re.sub(r"^[a-z]+://", "", name)  # tolerate pasted URLs
    name = name.split("/")[0].split(":")[0]
    if strip_www and name.startswith("www.") and name.count(".") >= 2:
        name = name[4:]
    return name


def valid_domain(name):
    if not name or len(name) > 253 or "." not in name:
        return False
    return all(re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label) for label in name.split("."))


def base_domain(name):
    """Registrable domain: 'a.b.example.com' -> 'example.com', 'x.example.co.uk' -> 'example.co.uk'."""
    name = (name or "").lower().rstrip(".")
    parts = name.split(".")
    if len(parts) <= 2:
        return name
    if ".".join(parts[-2:]) in TWO_PART_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_local_name(name):
    name = name.lower().rstrip(".")
    if not name or "." not in name:
        return True  # single-label names like "wpad" or "nas"
    if name == "localhost" or name.endswith(LOCAL_SUFFIXES):
        return True
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


class Whitelist:
    """Matching rules: domain entries cover all subdomains, exact entries cover one name."""

    def __init__(self, domains=(), exact=()):
        self.domains = {normalize_domain(d) for d in domains if d}
        self.exact = {normalize_domain(e) for e in exact if e}

    def match(self, name):
        """Return 'exact', 'domain' or None."""
        name = name.lower().rstrip(".")
        if name in self.exact:
            return "exact"
        parts = name.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in self.domains:
                return "domain"
        return None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
class Config:
    DEFAULTS = {
        "version": VERSION,
        "password": "",
        "allow_domains": list(DEFAULT_WHITELIST),
        "allow_exact": [],
        "log_only": False,
        "paused_until": 0,  # 0 = not paused, -1 = paused until resumed, else unix time
        "created": "",
    }

    def __init__(self, path=CONFIG_FILE):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.data = copy.deepcopy(self.DEFAULTS)
        self._mtime = None
        self._whitelist = Whitelist(self.data["allow_domains"], self.data["allow_exact"])

    # -- persistence --------------------------------------------------------
    def load(self):
        with self.lock:
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            data = copy.deepcopy(self.DEFAULTS)
            data.update(loaded)
            self.data = data
            self._mtime = self.path.stat().st_mtime
            self._rebuild()
        return self

    def save(self):
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
            self._mtime = self.path.stat().st_mtime
            self._rebuild()

    def reload_if_changed(self):
        """Pick up edits made by someone else (manual edits, another process)."""
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return False
        if mtime != self._mtime:
            try:
                self.load()
                return True
            except Exception as exc:
                log_err("config reload failed", exc)
        return False

    def _rebuild(self):
        self._whitelist = Whitelist(self.data["allow_domains"], self.data["allow_exact"])

    # -- accessors -----------------------------------------------------------
    @property
    def whitelist(self):
        return self._whitelist

    def check_password(self, password):
        return bool(self.data.get("password")) and verify_password(password or "", self.data["password"])

    def set_password(self, password):
        with self.lock:
            self.data["password"] = hash_password(password)
            self.save()

    def add_allowed(self, name, exact=False):
        name = normalize_domain(name, strip_www=not exact)
        if not valid_domain(name):
            raise ValueError(f"'{name}' is not a valid website name")
        with self.lock:
            key = "allow_exact" if exact else "allow_domains"
            if name not in self.data[key]:
                self.data[key].append(name)
                self.data[key].sort()
                self.save()
        return name

    def remove_allowed(self, name, exact=False):
        name = normalize_domain(name)
        with self.lock:
            key = "allow_exact" if exact else "allow_domains"
            if name in self.data[key]:
                self.data[key].remove(name)
                self.save()
                return True
        return False

    def set_option(self, key, value):
        with self.lock:
            self.data[key] = value
            self.save()

    def is_paused(self):
        until = self.data.get("paused_until", 0)
        if until == -1:
            return True
        if until and until > time.time():
            return True
        if until and until <= time.time():
            # Expired pause: clear it so status is accurate.
            try:
                self.set_option("paused_until", 0)
            except Exception:
                pass
        return False

    def public_view(self):
        """Config without secrets, for the manager."""
        with self.lock:
            return {
                "allow_domains": sorted(self.data["allow_domains"]),
                "allow_exact": sorted(self.data["allow_exact"]),
                "log_only": bool(self.data.get("log_only")),
                "paused_until": self.data.get("paused_until", 0),
                "paused": self.is_paused(),
                "version": self.data.get("version"),
            }


# ---------------------------------------------------------------------------
# Blocked-traffic log
# ---------------------------------------------------------------------------
class BlockedLog:
    """Tab-separated: time, name, qtype. Trimmed to half when it exceeds LOG_MAX_BYTES."""

    def __init__(self, path=BLOCKED_LOG, max_bytes=LOG_MAX_BYTES):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.lock = threading.Lock()
        self._writes = 0

    def append(self, name, qtype):
        line = f"{now_iso()}\t{name}\t{qtype}\n"
        with self.lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line)
                self._writes += 1
                if self._writes % 200 == 0:
                    self._trim()
            except Exception as exc:
                log_err("blocked log write failed", exc)

    def _trim(self):
        try:
            if self.path.stat().st_size <= self.max_bytes:
                return
            data = self.path.read_bytes()
            keep = data[-self.max_bytes // 2:]
            nl = keep.find(b"\n")
            keep = keep[nl + 1:] if nl >= 0 else keep
            self.path.write_bytes(keep)
        except Exception as exc:
            log_err("blocked log trim failed", exc)

    def clear(self):
        with self.lock:
            try:
                self.path.write_text("", encoding="utf-8")
            except FileNotFoundError:
                pass

    def read_text(self):
        try:
            return self.path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return ""

    def recent_domains(self, seconds=120, limit=8):
        """Base domains blocked within the last `seconds`, newest first."""
        try:
            size = self.path.stat().st_size
            with open(self.path, "rb") as fh:
                fh.seek(max(0, size - 65536))
                tail = fh.read().decode("utf-8", "replace")
        except OSError:
            return []
        cutoff = (dt.datetime.now() - dt.timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")
        seen = []
        for line in reversed(tail.splitlines()):
            parts = line.split("\t")
            if len(parts) < 2 or parts[0] < cutoff:
                continue
            dom = base_domain(parts[1].lower().rstrip("."))
            if dom and dom not in seen:
                seen.append(dom)
            if len(seen) >= limit:
                break
        return seen


def parse_blocked_log(text):
    """Aggregate log lines per registrable domain.

    Returns a list of dicts sorted by last_seen (newest first):
    {domain, hits, first_seen, last_seen, last_name}
    """
    agg = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0]:
            continue
        when, name = parts[0], parts[1].lower().rstrip(".")
        if not name:
            continue
        dom = base_domain(name)
        entry = agg.get(dom)
        if entry is None:
            agg[dom] = {"domain": dom, "hits": 1, "first_seen": when, "last_seen": when, "last_name": name}
        else:
            entry["hits"] += 1
            if when >= entry["last_seen"]:
                entry["last_seen"] = when
                entry["last_name"] = name
    return sorted(agg.values(), key=lambda e: e["last_seen"], reverse=True)


# ---------------------------------------------------------------------------
# DNS filter
# ---------------------------------------------------------------------------
class Resolver:
    """Decides what to answer. Pure logic, easy to unit test."""

    BLOCK_TTL = 1

    def __init__(self, config, blocked_log, upstreams=UPSTREAMS, forwarder=None, block_v4="127.0.0.1", block_v6="::1"):
        self.config = config
        self.blocked_log = blocked_log
        self.upstreams = upstreams
        self.forwarder = forwarder or self.forward_upstream
        self.block_v4 = block_v4
        self.block_v6 = block_v6
        self.blocked_count = 0

    def decide(self, qname):
        """Return 'local', 'allow' or 'block' for a query name."""
        if is_local_name(qname):
            return "local"
        if self.config.whitelist.match(qname):
            return "allow"
        return "block"

    def handle(self, data, tcp=False):
        """Take raw request bytes, return raw response bytes (or None to drop)."""
        try:
            request = DNSRecord.parse(data)
        except Exception:
            return None
        if not request.questions:
            return self._error(request, RCODE.FORMERR)
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE.get(request.q.qtype, str(request.q.qtype))
        decision = self.decide(qname)

        if decision == "block":
            self.blocked_count += 1
            paused = self.config.is_paused()
            log_only = bool(self.config.data.get("log_only"))
            if not paused:
                self.blocked_log.append(qname, qtype)
            if paused or log_only:
                decision = "allow"

        if decision == "block":
            return self._block_reply(request).pack()

        response = self.forwarder(data, tcp)
        if response is None:
            return self._error(request, RCODE.SERVFAIL)
        return response

    def _error(self, request, rcode):
        reply = request.reply()
        reply.header.rcode = rcode
        return reply.pack()

    def _block_reply(self, request):
        reply = request.reply()
        qtype = request.q.qtype
        if qtype in (QTYPE.A, QTYPE.ANY):
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(self.block_v4), ttl=self.BLOCK_TTL))
        if qtype in (QTYPE.AAAA, QTYPE.ANY):
            reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(self.block_v6), ttl=self.BLOCK_TTL))
        # Other types (HTTPS/65, TXT, MX, ...) get an empty NOERROR answer.
        return reply

    def forward_upstream(self, data, tcp=False):
        """Send the raw query to the upstream resolvers; return raw response or None."""
        for host, port in self.upstreams:
            try:
                resp = self._udp_query(host, port, data)
                if resp is None:
                    continue
                try:
                    truncated = DNSRecord.parse(resp).header.tc
                except Exception:
                    truncated = False
                if truncated or tcp:
                    tcp_resp = self._tcp_query(host, port, data)
                    if tcp_resp:
                        return tcp_resp
                return resp
            except Exception:
                continue
        return None

    @staticmethod
    def _udp_query(host, port, data):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(UPSTREAM_TIMEOUT)
            sock.sendto(data, (host, port))
            try:
                resp, _ = sock.recvfrom(4096)
            except socket.timeout:
                return None
        return resp

    @staticmethod
    def _tcp_query(host, port, data):
        try:
            with socket.create_connection((host, port), timeout=UPSTREAM_TIMEOUT) as sock:
                sock.sendall(len(data).to_bytes(2, "big") + data)
                head = _recv_exact(sock, 2)
                if not head:
                    return None
                return _recv_exact(sock, int.from_bytes(head, "big"))
        except OSError:
            return None


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class UDPDNSServer(threading.Thread):
    def __init__(self, resolver, host, port):
        super().__init__(daemon=True, name=f"dns-udp-{host}")
        self.resolver = resolver
        self.host, self.port = host, port
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="dns")
        self.running = True

    def run(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                if self.running:
                    time.sleep(0.05)
                continue
            self.pool.submit(self._respond, data, addr)

    def _respond(self, data, addr):
        try:
            resp = self.resolver.handle(data)
            if resp:
                self.sock.sendto(resp, addr)
        except Exception as exc:
            log_err("udp dns error", exc)

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass


class _TCPDNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            head = _recv_exact(self.request, 2)
            if not head:
                return
            data = _recv_exact(self.request, int.from_bytes(head, "big"))
            if not data:
                return
            resp = self.server.resolver.handle(data, tcp=True)
            if resp:
                self.request.sendall(len(resp).to_bytes(2, "big") + resp)
        except OSError:
            pass
        except Exception as exc:
            log_err("tcp dns error", exc)


class TCPDNSServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, resolver, host, port):
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.resolver = resolver
        super().__init__((host, port), _TCPDNSHandler)


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------
def _crypto():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    return x509, hashes, serialization, rsa, ExtendedKeyUsageOID, NameOID


def ensure_ca():
    """Create the local root CA if missing. Returns (key, cert) objects."""
    x509, hashes, serialization, rsa, _, NameOID = _crypto()
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    if CA_KEY_FILE.exists() and CA_CRT_FILE.exists():
        key = serialization.load_pem_private_key(CA_KEY_FILE.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(CA_CRT_FILE.read_bytes())
        return key, cert

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, APP_NAME),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365 * 10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    CA_KEY_FILE.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    CA_CRT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def ca_fingerprint_sha1():
    x509, hashes, *_ = _crypto()
    cert = x509.load_pem_x509_certificate(CA_CRT_FILE.read_bytes())
    return cert.fingerprint(hashes.SHA1()).hex()


class CertMinter:
    """Mints per-host leaf certificates signed by the local CA, on demand (SNI)."""

    LEAF_DAYS = 300

    def __init__(self):
        self.x509, self.hashes, self.serialization, rsa, self.EKU, self.NameOID = _crypto()
        self.ca_key, self.ca_cert = ensure_ca()
        self.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.leaf_key_pem = self.leaf_key.private_bytes(
            self.serialization.Encoding.PEM, self.serialization.PrivateFormat.PKCS8,
            self.serialization.NoEncryption())
        self.contexts = {}
        self.lock = threading.Lock()
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        for old in CERT_DIR.glob("*.pem"):
            try:
                old.unlink()
            except OSError:
                pass

    def context_for(self, host):
        host = (host or "localhost").lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9.\-_:]{1,253}", host):
            host = "localhost"
        with self.lock:
            entry = self.contexts.get(host)
            if entry and entry[1] > time.time():
                return entry[0]
            ctx = self._make_context(host)
            self.contexts[host] = (ctx, time.time() + 86400 * (self.LEAF_DAYS - 30))
            if len(self.contexts) > 2000:
                self.contexts.pop(next(iter(self.contexts)))
            return ctx

    def _make_context(self, host):
        x509 = self.x509
        san = [x509.DNSName(host)]
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            pass
        if host in ("localhost", "127.0.0.1", "::1"):
            san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                   x509.IPAddress(ipaddress.ip_address("::1"))]
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(self.NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self.ca_cert.subject)
            .public_key(self.leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=self.LEAF_DAYS))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([self.EKU.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()), critical=False)
            .sign(self.ca_key, self.hashes.SHA256())
        )
        pem_path = CERT_DIR / (re.sub(r"[^a-z0-9.\-]", "_", host) + ".pem")
        pem_path.write_bytes(cert.public_bytes(self.serialization.Encoding.PEM) + self.leaf_key_pem
                             + self.ca_cert.public_bytes(self.serialization.Encoding.PEM))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(pem_path))
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass
        return ctx

    def base_context(self):
        """Context used before SNI is known; switches certificate via the SNI callback."""
        ctx = self.context_for("localhost")
        base = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        base.minimum_version = ssl.TLSVersion.TLSv1_2
        base.load_cert_chain(str(CERT_DIR / "localhost.pem"))
        try:
            base.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass

        def sni_callback(sslobj, servername, _ctx):
            try:
                sslobj.context = self.context_for(servername or "localhost")
            except Exception as exc:
                log_err(f"sni callback failed for {servername!r}", exc)

        base.sni_callback = sni_callback
        _ = ctx
        return base


# ---------------------------------------------------------------------------
# Block page + local API (HTTP and HTTPS)
# ---------------------------------------------------------------------------
BLOCK_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Content filtering</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
 background:#0f1115;color:#e6e8ee;font:16px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.card{width:min(520px,92vw);background:#171a21;border:1px solid #262a33;border-radius:16px;padding:36px 32px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.lock{width:64px;height:64px;margin:0 auto 18px;color:#f0b429}
h1{margin:0 0 6px;font-size:22px;font-weight:600;letter-spacing:.2px}
.domain{font-family:ui-monospace,Consolas,monospace;font-size:17px;color:#8ab4ff;word-break:break-all;margin:10px 0 14px}
p{margin:0 0 8px;color:#aab1c0}
details{margin-top:26px;text-align:left;border-top:1px solid #262a33;padding-top:18px}
summary{cursor:pointer;color:#cfd4df;font-weight:500;list-style:none;display:flex;align-items:center;gap:8px}
summary::-webkit-details-marker{display:none}
summary::before{content:"\\25B8";font-size:14px;color:#8a93a6;transition:transform .15s}
details[open] summary::before{transform:rotate(90deg)}
form{margin-top:14px;display:flex;flex-direction:column;gap:10px}
input[type=password]{width:100%;padding:11px 12px;border-radius:10px;border:1px solid #2e3340;background:#0f1115;color:#e6e8ee;font-size:15px}
input:focus{outline:2px solid #4c7dff;border-color:transparent}
button{padding:11px 14px;border-radius:10px;border:1px solid #3b4252;background:#222733;color:#e6e8ee;font-size:14px;cursor:pointer;text-align:left}
button:hover{background:#2a3040;border-color:#4c7dff}
button b{color:#8ab4ff;font-family:ui-monospace,Consolas,monospace;font-weight:600}
.msg{margin-top:12px;padding:10px 12px;border-radius:10px;font-size:14px}
.err{background:#3a1d22;color:#ff9aa6;border:1px solid #5a2a33}
.ok{background:#15301f;color:#8fe3a8;border:1px solid #23523a}
.foot{margin-top:22px;font-size:12px;color:#5f6775}
.extras{margin-top:6px;padding:10px 12px;border-radius:10px;background:#12151b;border:1px solid #262a33;font-size:13px;color:#aab1c0}
.extras label{display:flex;align-items:center;gap:8px;margin:4px 0;cursor:pointer}
.extras b{color:#cfd4df;font-family:ui-monospace,Consolas,monospace;font-weight:500}
</style></head><body>
<div class="card">
<svg class="lock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
<rect x="4" y="10.5" width="16" height="10" rx="2.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15.5" r="1.2" fill="currentColor"/></svg>
<h1>Content filtering</h1>
<div class="domain">__HOST__</div>
<p>This website is blocked on this computer.</p>
__MESSAGE__
<details __OPEN__>
<summary>Administrator? Allow this website</summary>
<form method="post" action="/__dnsguard/allow">
<input type="hidden" name="host" value="__HOST__">
<input type="hidden" name="url" value="__URL__">
<input type="password" name="password" placeholder="Password" autocomplete="current-password" required autofocus>
<button type="submit" name="mode" value="exact">Allow <b>__HOST__</b> only</button>
<button type="submit" name="mode" value="domain">Allow <b>__BASE__</b> (and all subdomains)</button>
__EXTRAS__
</form>
</details>
<div class="foot">DNSGuard __VERSION__</div>
</div></body></html>"""

ALLOWED_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Website allowed</title>
<style>:root{color-scheme:dark}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f1115;color:#e6e8ee;font:16px/1.5 system-ui,Segoe UI,sans-serif}
.card{width:min(520px,92vw);background:#171a21;border:1px solid #262a33;border-radius:16px;padding:36px 32px;text-align:center}
h1{font-size:22px;margin:0 0 10px;color:#8fe3a8}p{color:#aab1c0;margin:6px 0}code{color:#8ab4ff}a{color:#8ab4ff}</style></head>
<body><div class="card"><h1>Allowed</h1><p><code>__NAME__</code> was added to the allowed websites.</p>
<p id="msg">Taking you to the page…</p>
<p><a href="__URL__">Continue</a></p></div>
<script>
// Browsers cache the old "blocked" address for up to a minute. Keep probing our own
// ping endpoint; once the browser no longer reaches the filter, go to the real page.
(function () {
  var url = __URL_JSON__, tries = 0, msg = document.getElementById('msg');
  function go() { location.replace(url); }
  function again() {
    if (tries > 40) { return go(); }
    msg.textContent = 'Waiting for the browser to refresh its address cache\u2026 (' + (tries * 2) + 's)';
    setTimeout(check, 2000);
  }
  function check() {
    tries++;
    fetch('/__dnsguard/ping?t=' + Date.now(), {cache: 'no-store', credentials: 'omit', redirect: 'manual'})
      .then(function (r) {
        // A response without the filter's header comes from the real site: the browser has the new address.
        if (r.headers.get('X-DNSGuard') === 'ping') { again(); } else { go(); }
      })
      .catch(function () { if (tries >= 3) { go(); } else { again(); } });
  }
  setTimeout(check, 1200);
})();
</script></body></html>"""


def render_block_page(host, url, message="", open_form=False, extras=()):
    host = normalize_host_header(host)
    base = base_domain(host)
    msg_html = ""
    if message:
        kind, text = message
        msg_html = f'<div class="msg {kind}">{html.escape(text)}</div>'
    extras = [e for e in extras if e and e != base]
    extras_html = ""
    if extras:
        boxes = "".join(f'<label><input type="checkbox" name="extra" value="{html.escape(e)}"> also allow <b>{html.escape(e)}</b></label>'
                        for e in extras)
        extras_html = ('<div class="extras">Other websites blocked in the last two minutes '
                       '(pages often need several, e.g. a login provider):' + boxes + '</div>')
    page = BLOCK_PAGE
    for key, val in (("__HOST__", html.escape(host)), ("__BASE__", html.escape(base)),
                     ("__URL__", html.escape(url, quote=True)), ("__MESSAGE__", msg_html),
                     ("__EXTRAS__", extras_html),
                     ("__OPEN__", "open" if open_form else ""), ("__VERSION__", VERSION)):
        page = page.replace(key, val)
    return page


def normalize_host_header(host):
    host = (host or "").strip().lower()
    if host.startswith("["):
        host = host.split("]")[0] + "]"
    else:
        host = host.split(":")[0]
    return host.rstrip(".") or "this website"


def safe_redirect_url(url, host):
    """Only redirect back to http(s) URLs on the same host; otherwise the host's root."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme in ("http", "https") and parsed.hostname and parsed.hostname.lower() == host.lower():
            return url
    except ValueError:
        pass
    return f"https://{host}/"


class BlockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "DNSGuard"
    sys_version = ""
    service = None  # set by Service

    BENIGN = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, socket.timeout,
              ssl.SSLEOFError, ssl.SSLZeroReturnError)

    def setup(self):
        self._t_accept = time.monotonic()
        ssl_ctx = getattr(self.server, "ssl_context", None)
        if ssl_ctx is not None:
            self.request.settimeout(10)
            try:
                self.request = ssl_ctx.wrap_socket(self.request, server_side=True)
            except Exception as exc:
                # Clients that do not trust our CA abort here (alerts); only unusual errors are logged.
                text = str(exc)
                if "alert" not in text and not isinstance(exc, self.BENIGN):
                    log_err_dedup(("handshake", type(exc).__name__, text[:80]), f"TLS handshake failed: {type(exc).__name__}: {text[:200]}")
                raise
        super().setup()

    def handle(self):
        self._t_handshake_done = time.monotonic()
        try:
            super().handle()
        except self.BENIGN:
            pass
        except (ssl.SSLError, OSError) as exc:
            log_err_dedup(("handle", type(exc).__name__, str(exc)[:80]),
                          f"request failed for {self.headers.get('Host', '?') if getattr(self, 'headers', None) else '?'}: "
                          f"{type(exc).__name__}: {str(exc)[:200]}")
        except Exception as exc:
            log_err("unexpected error in block server", exc)

    def finish(self):
        try:
            super().finish()
        except (ssl.SSLError, OSError):
            pass
        total = time.monotonic() - getattr(self, "_t_accept", time.monotonic())
        # Browsers open spare connections and never send a request on them; those are not slow requests.
        if total > 3 and getattr(self, "command", None):
            hs = getattr(self, "_t_handshake_done", self._t_accept) - self._t_accept
            log_err_dedup(("slow", self.command if hasattr(self, "command") else "?"),
                          f"slow request: total {total:.1f}s (handshake {hs:.1f}s) "
                          f"{getattr(self, 'command', '?')} {getattr(self, 'path', '?')} "
                          f"host={self.headers.get('Host', '?') if getattr(self, 'headers', None) else '?'} "
                          f"threads={threading.active_count()}")

    def log_message(self, fmt, *args):  # quiet
        pass

    # -- helpers --------------------------------------------------------------
    def _host(self):
        return normalize_host_header(self.headers.get("Host", ""))

    def _url(self):
        scheme = "https" if getattr(self.server, "ssl_context", None) else "http"
        return f"{scheme}://{self.headers.get('Host', self._host())}{self.path}"

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 64 * 1024:
            raise ValueError("body too large")
        return self.rfile.read(length) if length else b""

    # -- routes ----------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == API_PREFIX + "api/status":
            return self._send(200, json.dumps(self.service.status()), "application/json")
        if path == API_PREFIX + "ping":
            return self._send(200, '{"dnsguard": true}', "application/json", {"X-DNSGuard": "ping"})
        if path == "/favicon.ico":
            return self._send(404, b"", "text/plain")
        if path == "/__dnsguard/ca.crt":
            try:
                return self._send(200, CA_CRT_FILE.read_bytes(), "application/x-pem-file")
            except OSError:
                return self._send(404, b"", "text/plain")
        self._send(200, self._block_page())

    def _block_page(self, message="", open_form=False):
        return render_block_page(self._host(), self._url(), message, open_form,
                                 extras=self.service.recent_blocked())

    do_HEAD = do_GET

    def do_POST(self):
        path = self.path.split("?")[0]
        try:
            body = self._read_body()
        except Exception:
            return self._send(400, "bad request", "text/plain")
        if path == API_PREFIX + "allow":
            return self._allow_from_page(body)
        if path == API_PREFIX + "api":
            return self._api(body)
        self._send(200, self._block_page())

    def _allow_from_page(self, body):
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        get = lambda k: (form.get(k) or [""])[0]
        host = normalize_host_header(get("host") or self._host())
        url = safe_redirect_url(get("url"), host)
        mode = get("mode")
        password = get("password")
        page_host = self._host()

        wait = self.service.limiter.retry_after()
        if wait:
            return self._send(429, self._block_page(("err", f"Too many wrong passwords. Try again in {wait} seconds."), True))
        if not self.service.config.check_password(password):
            self.service.limiter.record_failure()
            return self._send(403, self._block_page(("err", "Wrong password."), True))
        self.service.limiter.reset()
        try:
            name = self.service.allow(host if mode == "exact" else base_domain(host), exact=(mode == "exact"))
            for extra in form.get("extra") or []:
                extra = normalize_domain(extra, strip_www=True)
                if valid_domain(extra):
                    self.service.config.add_allowed(extra)
            if form.get("extra"):
                refresh_dns_caches()
        except ValueError as exc:
            return self._send(400, self._block_page(("err", str(exc)), True))
        page = (ALLOWED_PAGE.replace("__URL__", html.escape(url, quote=True))
                .replace("__URL_JSON__", json.dumps(url).replace("<", "\\u003c"))
                .replace("__NAME__", html.escape(name)))
        self._send(200, page)

    def _api(self, body):
        if self.headers.get(API_HEADER) != "1":
            return self._send(403, json.dumps({"ok": False, "error": "missing header"}), "application/json")
        try:
            req = json.loads(body.decode("utf-8") or "{}")
        except ValueError:
            return self._send(400, json.dumps({"ok": False, "error": "bad json"}), "application/json")
        code, result = self.service.api(req)
        self._send(code, json.dumps(result), "application/json")


class BlockHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host, port, ssl_context=None):
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.ssl_context = ssl_context
        super().__init__((host, port), BlockHandler)


# ---------------------------------------------------------------------------
# The filter service
# ---------------------------------------------------------------------------
class Service:
    def __init__(self, dns_port=53, http_port=80, https_port=443, manage_dns=True):
        self.dns_port, self.http_port, self.https_port = dns_port, http_port, https_port
        self.manage_dns = manage_dns
        self.config = Config()
        self.blocked_log = BlockedLog()
        self.limiter = RateLimiter()
        self.started = time.time()
        self.servers = []
        self.threads = []
        self.stop_event = threading.Event()
        self.resolver = None
        self.minter = None

    # -- lifecycle -------------------------------------------------------------
    def start(self):
        self.config.load()
        self.resolver = Resolver(self.config, self.blocked_log)
        self.minter = CertMinter()
        BlockHandler.service = self

        for host in ("127.0.0.1", "::1"):
            self._start_listener(lambda h=host: UDPDNSServer(self.resolver, h, self.dns_port), f"DNS/UDP {host}:{self.dns_port}")
            self._start_listener(lambda h=host: TCPDNSServer(self.resolver, h, self.dns_port), f"DNS/TCP {host}:{self.dns_port}")
            self._start_listener(lambda h=host: BlockHTTPServer(h, self.http_port), f"HTTP {host}:{self.http_port}")
            self._start_listener(lambda h=host: BlockHTTPServer(h, self.https_port, self.minter.base_context()), f"HTTPS {host}:{self.https_port}")

        if not any(isinstance(s, UDPDNSServer) for s in self.servers):
            raise RuntimeError(f"could not bind DNS port {self.dns_port}")

        t = threading.Thread(target=self._housekeeping, daemon=True, name="housekeeping")
        t.start()
        self.threads.append(t)
        if self.manage_dns and IS_WINDOWS and is_admin() and INSTALL_MARKER.exists():
            t = threading.Thread(target=self._dns_reapply_loop, daemon=True, name="dns-reapply")
            t.start()
            self.threads.append(t)

    def _start_listener(self, factory, label):
        try:
            server = factory()
        except OSError as exc:
            log_err(f"cannot listen on {label}: {exc}")
            return
        if isinstance(server, threading.Thread):
            server.start()
        else:
            threading.Thread(target=server.serve_forever, daemon=True, name=label).start()
        self.servers.append(server)

    def serve_forever(self):
        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        finally:
            self.stop()

    def stop(self):
        self.stop_event.set()
        for s in self.servers:
            try:
                if isinstance(s, UDPDNSServer):
                    s.stop()
                else:
                    s.shutdown()
                    s.server_close()
            except Exception:
                pass

    def _housekeeping(self):
        while not self.stop_event.wait(2):
            try:
                self.config.reload_if_changed()
            except Exception as exc:
                log_err("housekeeping", exc)

    def _dns_reapply_loop(self):
        # Give the network stack a moment after boot, then keep adapters pointed at us.
        time.sleep(5)
        while not self.stop_event.is_set():
            try:
                apply_dns_to_adapters()
            except Exception as exc:
                log_err("dns re-apply failed", exc)
            self.stop_event.wait(DNS_REAPPLY_SECONDS)

    # -- operations shared by block page, API and CLI ----------------------------
    def allow(self, name, exact=False):
        name = self.config.add_allowed(name, exact=exact)
        refresh_dns_caches()
        return name

    def recent_blocked(self):
        try:
            return self.blocked_log.recent_domains()
        except Exception as exc:
            log_err("recent_domains failed", exc)
            return []

    def status(self):
        return {
            "ok": True,
            "running": True,
            "version": VERSION,
            "paused": self.config.is_paused(),
            "paused_until": self.config.data.get("paused_until", 0),
            "log_only": bool(self.config.data.get("log_only")),
            "uptime": int(time.time() - self.started),
            "blocked_since_start": self.resolver.blocked_count if self.resolver else 0,
            "installed": INSTALL_MARKER.exists(),
            "ports": {"dns": self.dns_port, "http": self.http_port, "https": self.https_port},
        }

    def api(self, req):
        """Handle a manager/CLI request. Returns (http_code, dict)."""
        action = req.get("action")
        if action == "status":
            return 200, self.status()
        wait = self.limiter.retry_after()
        if wait:
            return 429, {"ok": False, "error": f"Too many wrong passwords. Try again in {wait} seconds.", "retry_after": wait}
        if not self.config.check_password(req.get("password", "")):
            self.limiter.record_failure()
            return 403, {"ok": False, "error": "Wrong password."}
        self.limiter.reset()
        try:
            return 200, self._api_action(action, req)
        except ValueError as exc:
            return 400, {"ok": False, "error": str(exc)}
        except Exception as exc:
            log_err(f"api action {action} failed", exc)
            return 500, {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def _api_action(self, action, req):
        cfg = self.config
        if action == "login":
            return {"ok": True, "config": cfg.public_view(), "status": self.status()}
        if action == "get_config":
            return {"ok": True, "config": cfg.public_view()}
        if action == "allow":
            name = self.allow(req.get("name", ""), exact=bool(req.get("exact")))
            return {"ok": True, "name": name, "config": cfg.public_view()}
        if action == "remove":
            removed = cfg.remove_allowed(req.get("name", ""), exact=bool(req.get("exact")))
            refresh_dns_caches()
            return {"ok": True, "removed": removed, "config": cfg.public_view()}
        if action == "blocked":
            return {"ok": True, "entries": parse_blocked_log(self.blocked_log.read_text())}
        if action == "clear_log":
            self.blocked_log.clear()
            return {"ok": True}
        if action == "change_password":
            problem = password_problem(req.get("new_password"))
            if problem:
                raise ValueError(problem)
            cfg.set_password(req["new_password"])
            return {"ok": True}
        if action == "pause":
            minutes = int(req.get("minutes") or 0)
            cfg.set_option("paused_until", -1 if minutes <= 0 else int(time.time() + minutes * 60))
            refresh_dns_caches()
            return {"ok": True, "status": self.status()}
        if action == "resume":
            cfg.set_option("paused_until", 0)
            refresh_dns_caches()
            return {"ok": True, "status": self.status()}
        if action == "set_log_only":
            cfg.set_option("log_only", bool(req.get("value")))
            refresh_dns_caches()
            return {"ok": True, "status": self.status()}
        if action == "uninstall":
            if not INSTALL_MARKER.exists():
                raise ValueError("DNSGuard is not installed on this computer.")
            threading.Thread(target=self._uninstall_later, daemon=True).start()
            return {"ok": True, "message": "Uninstalling. Internet settings are being restored."}
        raise ValueError(f"unknown action {action!r}")

    def _uninstall_later(self):
        time.sleep(1.0)  # let the HTTP response reach the manager first
        try:
            uninstall_core(stop_service=False)
        except Exception as exc:
            log_err("uninstall from service failed", exc)
        finally:
            schedule_self_cleanup()
            os._exit(0)


# ---------------------------------------------------------------------------
# Windows integration: DNS, CA store, policies, task, shortcuts, ACLs
# ---------------------------------------------------------------------------
def flush_dns_cache():
    if IS_WINDOWS:
        try:
            run_cmd(["ipconfig", "/flushdns"], timeout=30)
        except Exception as exc:
            log_err("flushdns failed", exc)


def toggle_hosts_marker(path=HOSTS_FILE, remove=False):
    """Swap the DNSGuard marker line in the hosts file (or remove it). Returns True if written.

    Chrome and Edge re-read the hosts file on change and drop their DNS cache, so a page
    allowed a moment ago loads right away instead of after their one-minute cache expires.
    Needs admin rights; failures are logged and otherwise ignored.
    """
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        log_err_dedup(("hosts-read",), f"hosts file not readable: {exc}")
        return False
    newline = b"\r\n" if b"\r\n" in data else b"\n"
    lines = data.split(newline)
    had_a = any(HOSTS_MARKERS[0] in line for line in lines)
    kept = [line for line in lines if b"dnsguard-" not in line or b"DNSGuard" not in line]
    while kept and kept[-1] == b"":
        kept.pop()
    if not remove:
        kept.append(HOSTS_MARKERS[1] if had_a else HOSTS_MARKERS[0])
    new = newline.join(kept) + newline
    if new == data:
        return False
    try:
        Path(path).write_bytes(new)
        return True
    except OSError as exc:
        log_err_dedup(("hosts-write",), f"hosts file not writable: {exc}")
        return False


def refresh_dns_caches():
    """Called after any change that alters DNS answers: flush Windows, nudge browsers."""
    flush_dns_cache()
    if IS_WINDOWS and not SANDBOX:
        toggle_hosts_marker()


def adapters_info():
    """List network adapters with their current DNS servers."""
    script = r"""
$ErrorActionPreference='SilentlyContinue'
$out = @()
foreach ($a in Get-NetAdapter) {
  $v4 = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses)
  $v6 = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6).ServerAddresses)
  $out += [pscustomobject]@{ Index=[int]$a.ifIndex; Name=[string]$a.Name; Guid=[string]$a.InterfaceGuid;
                              Status=[string]$a.Status; Desc=[string]$a.InterfaceDescription; V4=$v4; V6=$v6 }
}
ConvertTo-Json -InputObject $out -Compress -Depth 4
"""
    res = run_ps(script, timeout=90)
    text = (res.stdout or "").strip()
    if not text:
        raise RuntimeError(f"Get-NetAdapter failed: {res.stderr.strip()}")
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    for a in data:
        a["V4"] = [x for x in (a.get("V4") or []) if x]
        a["V6"] = [x for x in (a.get("V6") or []) if x]
    return data


def _registry_nameserver(guid, v6=False):
    """Static DNS servers configured in the registry ('' means DHCP / automatic)."""
    import winreg

    base = r"SYSTEM\CurrentControlSet\Services\%s\Parameters\Interfaces\%s" % ("Tcpip6" if v6 else "Tcpip", guid)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
            value, _ = winreg.QueryValueEx(key, "NameServer")
            return value or ""
    except OSError:
        return ""


def load_snapshot():
    try:
        return json.loads(SNAPSHOT_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"adapters": {}}


def save_snapshot(snapshot):
    SNAPSHOT_FILE.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_FILE.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")


def _is_ours(servers):
    return bool(servers) and set(servers) <= {"127.0.0.1", "::1"}


def apply_dns_to_adapters():
    """Snapshot (first time) and point every connected adapter at 127.0.0.1 / ::1."""
    snapshot = load_snapshot()
    changed_snapshot = False
    for a in adapters_info():
        if a.get("Status") != "Up":
            continue
        guid = a.get("Guid") or a["Name"]
        if guid not in snapshot["adapters"]:
            v4_static = _registry_nameserver(guid, v6=False)
            v6_static = _registry_nameserver(guid, v6=True)
            # If the adapter already points at us (e.g. snapshot lost), treat as automatic.
            if _is_ours(a["V4"]) or _is_ours(a["V6"]):
                v4_static, v6_static = "", ""
            snapshot["adapters"][guid] = {
                "name": a["Name"], "index": a["Index"],
                "v4_static": [s for s in v4_static.replace(" ", ",").split(",") if s],
                "v6_static": [s for s in v6_static.replace(" ", ",").split(",") if s],
                "seen_v4": a["V4"], "seen_v6": a["V6"], "time": now_iso(),
            }
            changed_snapshot = True
        if _is_ours(a["V4"]) and (not a["V6"] or _is_ours(a["V6"])):
            continue
        res = run_ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(a['Index'])} -ServerAddresses @('127.0.0.1','::1')")
        if res.returncode != 0 and res.stderr.strip():
            log_err(f"Set-DnsClientServerAddress failed for {a['Name']}: {res.stderr.strip()}")
    if changed_snapshot:
        save_snapshot(snapshot)


def restore_dns_from_snapshot():
    """Put every adapter back the way it was (static list or DHCP)."""
    snapshot = load_snapshot()
    current = {}
    try:
        for a in adapters_info():
            current[a.get("Guid") or a["Name"]] = a
    except Exception as exc:
        log_err("adapters_info during restore failed", exc)
    seen_indexes = set()
    for guid, entry in snapshot.get("adapters", {}).items():
        adapter = current.get(guid)
        index = adapter["Index"] if adapter else entry.get("index")
        if index is None:
            continue
        seen_indexes.add(index)
        servers = list(entry.get("v4_static") or []) + list(entry.get("v6_static") or [])
        if servers:
            quoted = ",".join(f"'{s}'" for s in servers)
            run_ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(index)} -ServerAddresses @({quoted})")
        else:
            run_ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(index)} -ResetServerAddresses")
    # Any adapter still pointing at loopback that we never recorded: reset to automatic.
    for guid, a in current.items():
        if a["Index"] in seen_indexes:
            continue
        if _is_ours(a["V4"]) or _is_ours(a["V6"]):
            run_ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(a['Index'])} -ResetServerAddresses")
    flush_dns_cache()


def install_ca_in_store():
    res = run_cmd(["certutil.exe", "-addstore", "-f", "Root", str(CA_CRT_FILE)])
    if res.returncode != 0:
        raise RuntimeError(f"certutil -addstore failed: {res.stdout.strip()} {res.stderr.strip()}")


def remove_ca_from_store():
    try:
        fp = ca_fingerprint_sha1()
        run_cmd(["certutil.exe", "-delstore", "Root", fp])
    except Exception:
        pass
    # Also remove any stale copies that match by name.
    run_cmd(["certutil.exe", "-delstore", "Root", CA_COMMON_NAME])


def set_browser_policies(enable=True):
    """Disable browser DNS-over-HTTPS (it would bypass the filter) and trust our CA in Firefox."""
    import winreg

    policies = [
        (r"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", winreg.REG_SZ, "off"),
        (r"SOFTWARE\Policies\Google\Chrome", "BuiltInDnsClientEnabled", winreg.REG_DWORD, 1),
        (r"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", winreg.REG_SZ, "off"),
        (r"SOFTWARE\Policies\Microsoft\Edge", "BuiltInDnsClientEnabled", winreg.REG_DWORD, 1),
        (r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled", winreg.REG_DWORD, 0),
        (r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked", winreg.REG_DWORD, 1),
        (r"SOFTWARE\Policies\Mozilla\Firefox\Certificates", "ImportEnterpriseRoots", winreg.REG_DWORD, 1),
    ]
    for path, name, kind, value in policies:
        try:
            if enable:
                with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, name, 0, kind, value)
            else:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, name)
        except OSError:
            pass
    if not enable:
        for path in (r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", r"SOFTWARE\Policies\Mozilla\Firefox\Certificates"):
            try:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, path)
            except OSError:
                pass


TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>DNSGuard whitelist web filter</Description><Author>DNSGuard</Author></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>10</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>__CMD__</Command><Arguments>__ARGS__</Arguments></Exec></Actions>
</Task>
"""


def create_scheduled_task():
    cmd = installed_command()
    xml = TASK_XML.replace("__CMD__", html.escape(cmd[0])).replace(
        "__ARGS__", html.escape(" ".join(_quote(a) for a in cmd[1:] + ["run"])))
    xml_path = PRIVATE_DIR / "task.xml"
    xml_path.write_text(xml, encoding="utf-16")
    res = run_cmd(["schtasks.exe", "/Create", "/TN", TASK_NAME, "/XML", str(xml_path), "/F"])
    if res.returncode != 0:
        raise RuntimeError(f"schtasks /Create failed: {res.stdout.strip()} {res.stderr.strip()}")


def start_scheduled_task():
    return run_cmd(["schtasks.exe", "/Run", "/TN", TASK_NAME]).returncode == 0


def stop_scheduled_task():
    run_cmd(["schtasks.exe", "/End", "/TN", TASK_NAME])


def delete_scheduled_task():
    run_cmd(["schtasks.exe", "/Delete", "/TN", TASK_NAME, "/F"])


def task_exists():
    return run_cmd(["schtasks.exe", "/Query", "/TN", TASK_NAME]).returncode == 0


# Runs `DNSGuard.exe logon` as each user (BUILTIN\Users) when they sign in.
LOGON_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>DNSGuard desktop picture and start page</Description><Author>DNSGuard</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><GroupId>S-1-5-32-545</GroupId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>false</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author"><Exec><Command>__CMD__</Command><Arguments>__ARGS__</Arguments></Exec></Actions>
</Task>
"""


def logon_task_xml():
    cmd = installed_command()
    return LOGON_TASK_XML.replace("__CMD__", html.escape(cmd[0])).replace(
        "__ARGS__", html.escape(" ".join(_quote(a) for a in cmd[1:] + ["logon"])))


def create_logon_task():
    xml_path = PRIVATE_DIR / "logon_task.xml"
    xml_path.write_text(logon_task_xml(), encoding="utf-16")
    res = run_cmd(["schtasks.exe", "/Create", "/TN", LOGON_TASK_NAME, "/XML", str(xml_path), "/F"])
    if res.returncode != 0:
        raise RuntimeError(f"schtasks /Create failed: {res.stdout.strip()} {res.stderr.strip()}")


def delete_logon_task():
    run_cmd(["schtasks.exe", "/Delete", "/TN", LOGON_TASK_NAME, "/F"])


def bundled_wallpaper():
    """The wallpaper shipped inside the exe (PyInstaller unpacks it to _MEIPASS)."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / "assets" / "wallpaper.jpg"


def set_desktop_wallpaper(path=WALLPAPER_FILE):
    """Set the current user's desktop picture (style: fill). Works on every Windows edition."""
    import winreg

    if not Path(path).exists():
        return False
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "WallpaperStyle", 0, winreg.REG_SZ, "10")
        winreg.SetValueEx(key, "TileWallpaper", 0, winreg.REG_SZ, "0")
    SPI_SETDESKWALLPAPER, SPIF_UPDATEINIFILE, SPIF_SENDCHANGE = 0x0014, 0x01, 0x02
    return bool(ctypes.windll.user32.SystemParametersInfoW(
        SPI_SETDESKWALLPAPER, 0, str(path), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE))


def create_shortcuts():
    cmd = installed_command()
    START_MENU_DIR.mkdir(parents=True, exist_ok=True)
    items = [("DNSGuard Manager", "manage", "Manage allowed websites and see blocked traffic"),
             ("Uninstall DNSGuard", "uninstall", "Remove DNSGuard from this computer")]
    lines = ["$ws = New-Object -ComObject WScript.Shell"]
    for title, arg, desc in items:
        lnk = START_MENU_DIR / f"{title}.lnk"
        args = " ".join(_quote(a) for a in cmd[1:] + [arg])
        lines.append(
            f"$s = $ws.CreateShortcut('{lnk}'); $s.TargetPath = '{cmd[0]}'; $s.Arguments = '{args}'; "
            f"$s.Description = '{desc}'; $s.WorkingDirectory = '{DATA_DIR}'; $s.Save()")
    run_ps("\n".join(lines))


def remove_shortcuts():
    shutil.rmtree(START_MENU_DIR, ignore_errors=True)


def register_uninstall_entry(enable=True):
    import winreg

    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DNSGuard"
    try:
        if enable:
            cmd = installed_command()
            uninstall = " ".join(_quote(a) for a in cmd + ["uninstall"])
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "DNSGuard web filter")
                winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, VERSION)
                winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "DNSGuard")
                winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(DATA_DIR))
                winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, uninstall)
                winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
        else:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, path)
    except OSError:
        pass


def harden_acls():
    """Users may read the public folder (logs, CA cert) but not the private folder."""
    if SANDBOX:
        return
    SYSTEM, ADMINS, USERS = "*S-1-5-18", "*S-1-5-32-544", "*S-1-5-32-545"
    run_cmd(["icacls.exe", str(DATA_DIR), "/inheritance:r",
             "/grant:r", f"{SYSTEM}:(OI)(CI)F", f"{ADMINS}:(OI)(CI)F", f"{USERS}:(OI)(CI)RX"])
    run_cmd(["icacls.exe", str(PRIVATE_DIR), "/inheritance:r",
             "/grant:r", f"{SYSTEM}:(OI)(CI)F", f"{ADMINS}:(OI)(CI)F"])


def schedule_self_cleanup():
    """Spawn a detached script that deletes the data folder once this process is gone."""
    if not IS_WINDOWS:
        return
    temp = Path(os.environ.get("TEMP") or os.environ.get("SystemRoot", r"C:\Windows") + r"\Temp")
    script = temp / "dnsguard_cleanup.cmd"
    # Only processes running from the installed copy are killed, so a DNSGuard.exe that
    # requested the uninstall from elsewhere (USB stick, dist folder) keeps running.
    kill_ps = (f"Get-Process {APP_NAME} -ErrorAction SilentlyContinue | "
               f"Where-Object {{ $_.Path -eq '{INSTALLED_EXE}' }} | Stop-Process -Force")
    script.write_text(
        "@echo off\r\n"
        "timeout /t 3 /nobreak >nul\r\n"
        f"powershell.exe -NoProfile -NonInteractive -Command \"{kill_ps}\" >nul 2>&1\r\n"
        f"schtasks /Delete /TN {TASK_NAME} /F >nul 2>&1\r\n"
        "timeout /t 2 /nobreak >nul\r\n"
        "for /l %%i in (1,1,15) do (\r\n"
        f"  rmdir /s /q \"{DATA_DIR}\" >nul 2>&1\r\n"
        f"  if not exist \"{DATA_DIR}\" goto done\r\n"
        "  timeout /t 1 /nobreak >nul\r\n"
        ")\r\n"
        ":done\r\n"
        "del \"%~f0\"\r\n", encoding="ascii")
    flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    for extra in (CREATE_BREAKAWAY_FROM_JOB, 0):
        try:
            subprocess.Popen(["cmd.exe", "/c", str(script)], creationflags=flags | extra, close_fds=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except OSError:
            continue


def kill_other_instances():
    """Stop every other DNSGuard.exe process (service, open managers).

    A one-file exe is two processes (bootloader parent + this one), so both are spared.
    """
    if FROZEN:
        run_cmd(["taskkill.exe", "/F", "/FI", f"PID ne {os.getpid()}", "/FI", f"PID ne {os.getppid()}",
                 "/IM", f"{APP_NAME}.exe"])


# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------
def is_installed():
    return INSTALL_MARKER.exists()


def port_in_use(port, host="127.0.0.1", udp=False):
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as s:
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True


def install_core(password, extra_allow=(), log_only=False, progress=print):
    """Perform the installation. Must run with admin rights."""
    progress("Creating folders")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    harden_acls()

    if FROZEN and Path(sys.executable).resolve() != INSTALLED_EXE.resolve():
        progress("Copying program")
        if INSTALLED_EXE.exists():
            stop_scheduled_task()      # upgrade: the running copy must be stopped before overwriting
            kill_other_instances()
            for _ in range(20):
                try:
                    shutil.copy2(sys.executable, INSTALLED_EXE)
                    break
                except PermissionError:
                    time.sleep(0.5)
            else:
                raise RuntimeError("could not replace the running DNSGuard.exe")
        else:
            shutil.copy2(sys.executable, INSTALLED_EXE)

    progress("Writing configuration")
    cfg = Config()
    if CONFIG_FILE.exists():
        try:
            cfg.load()
        except Exception:
            pass
    if password:
        cfg.data["password"] = hash_password(password)
    if START_PAGE_DOMAIN not in cfg.data["allow_domains"]:
        cfg.data["allow_domains"].append(START_PAGE_DOMAIN)  # upgrades keep the start page reachable
    cfg.data["created"] = cfg.data.get("created") or now_iso()
    cfg.data["version"] = VERSION
    cfg.data["log_only"] = bool(log_only)
    for name in extra_allow:
        name = normalize_domain(name, strip_www=True)
        if valid_domain(name) and name not in cfg.data["allow_domains"]:
            cfg.data["allow_domains"].append(name)
    cfg.data["allow_domains"].sort()
    cfg.save()

    progress("Creating local certificate authority")
    ensure_ca()
    install_ca_in_store()
    set_browser_policies(True)

    progress("Registering startup task")
    create_scheduled_task()
    if bundled_wallpaper().exists():
        shutil.copy2(bundled_wallpaper(), WALLPAPER_FILE)
    create_logon_task()
    create_shortcuts()
    register_uninstall_entry(True)
    INSTALL_MARKER.write_text(json.dumps({"version": VERSION, "installed": now_iso(),
                                          "exe": installed_command()[0]}), encoding="utf-8")

    progress("Starting the filter")
    start_scheduled_task()
    deadline = time.time() + 45  # the one-file exe unpacks itself on first start
    while time.time() < deadline:
        if ApiClient().status():
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("The filter service did not start. See dnsguard.err in " + str(DATA_DIR))

    progress("Pointing network adapters at the filter")
    apply_dns_to_adapters()
    flush_dns_cache()
    try:
        set_desktop_wallpaper()  # the installing user; everyone else gets it at their next sign-in
    except Exception as exc:
        log_err("set wallpaper failed", exc)


def uninstall_core(stop_service=True, progress=lambda m: None):
    """Undo everything install_core did. Must run with admin rights."""
    progress("Restoring network settings")
    try:
        restore_dns_from_snapshot()
    except Exception as exc:
        log_err("restore dns failed", exc)
    if stop_service:
        progress("Stopping the filter")
        stop_scheduled_task()
        kill_other_instances()
    progress("Removing task, shortcuts, policies and certificate")
    delete_scheduled_task()
    delete_logon_task()
    remove_shortcuts()
    set_browser_policies(False)
    register_uninstall_entry(False)
    remove_ca_from_store()
    toggle_hosts_marker(remove=True)
    try:
        INSTALL_MARKER.unlink()
    except OSError:
        pass
    flush_dns_cache()


# ---------------------------------------------------------------------------
# API client (manager, CLI)
# ---------------------------------------------------------------------------
class ApiClient:
    def __init__(self, port=None, timeout=5):
        self.port = port or int(os.environ.get("DNSGUARD_HTTP_PORT") or 80)
        self.timeout = timeout

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{API_PREFIX}{path}"

    def status(self):
        try:
            with urllib.request.urlopen(self._url("api/status"), timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data if data.get("ok") and data.get("version") else None
        except Exception:
            return None

    def call(self, action, password="", **kwargs):
        """Returns the response dict; raises ApiError with a readable message on failure."""
        body = json.dumps({"action": action, "password": password, **kwargs}).encode("utf-8")
        req = urllib.request.Request(self._url("api"), data=body, method="POST",
                                     headers={"Content-Type": "application/json", API_HEADER: "1"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                data = json.loads(exc.read().decode("utf-8"))
                raise ApiError(data.get("error") or f"HTTP {exc.code}", exc.code)
            except ValueError:
                raise ApiError(f"HTTP {exc.code}", exc.code)
        except urllib.error.URLError as exc:
            raise ApiError("The filter service is not running.", 0) from exc


class ApiError(Exception):
    def __init__(self, message, code=0):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Tk dialogs and the manager window
# ---------------------------------------------------------------------------
def ask_password_dialog(title, prompt, confirm=False, parent=None):
    """Modal password prompt. Returns the password or None if cancelled.

    With a parent window the dialog is a Toplevel of it (a second Tk root would run an
    event loop that never returns while the parent window exists).
    """
    import tkinter as tk
    from tkinter import messagebox, ttk

    if parent is None:
        root = tk.Tk()
    else:
        root = tk.Toplevel(parent)
        root.transient(parent)
    root.title(title)
    root.resizable(False, False)
    root.attributes("-topmost", True)
    result = {"value": None}

    frame = ttk.Frame(root, padding=16)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text=prompt, wraplength=360).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
    ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky="e", padx=(0, 8))
    pw1 = ttk.Entry(frame, show="*", width=32)
    pw1.grid(row=1, column=1, sticky="we")
    pw2 = None
    if confirm:
        ttk.Label(frame, text="Repeat:").grid(row=2, column=0, sticky="e", padx=(0, 8), pady=(6, 0))
        pw2 = ttk.Entry(frame, show="*", width=32)
        pw2.grid(row=2, column=1, sticky="we", pady=(6, 0))
    buttons = ttk.Frame(frame)
    buttons.grid(row=3, column=0, columnspan=2, sticky="e", pady=(14, 0))

    def ok(*_):
        value = pw1.get()
        if confirm:
            problem = password_problem(value)
            if problem:
                messagebox.showerror(title, problem, parent=root)
                return
            if value != pw2.get():
                messagebox.showerror(title, "The passwords do not match.", parent=root)
                return
        result["value"] = value
        root.destroy()

    def cancel(*_):
        root.destroy()

    ttk.Button(buttons, text="OK", command=ok, default="active").pack(side="right")
    ttk.Button(buttons, text="Cancel", command=cancel).pack(side="right", padx=(0, 8))
    root.bind("<Return>", ok)
    root.bind("<Escape>", cancel)
    pw1.focus_set()
    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_reqwidth()) // 2
    y = (root.winfo_screenheight() - root.winfo_reqheight()) // 3
    root.geometry(f"+{x}+{y}")
    if parent is None:
        root.mainloop()
    else:
        root.grab_set()
        root.lift()
        parent.wait_window(root)
    return result["value"]


class ManagerApp:
    REFRESH_MS = 15000

    def __init__(self, password=None):
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk = tk, ttk
        self.api = ApiClient()
        self.password = password
        self.config = {}
        self.root = tk.Tk()
        self.root.title(f"DNSGuard Manager {VERSION}")
        self.root.minsize(760, 520)
        try:
            ttk.Style().theme_use("vista")
        except Exception:
            pass
        self._build()
        self.root.after(100, self._startup)

    # -- UI construction --------------------------------------------------------
    def _build(self):
        tk, ttk = self.tk, self.ttk
        top = ttk.Frame(self.root, padding=(12, 10))
        top.pack(fill="x")
        self.status_var = tk.StringVar(value="Checking filter status…")
        self.status_label = ttk.Label(top, textvariable=self.status_var, font=("Segoe UI", 11, "bold"))
        self.status_label.pack(side="left")
        self.start_btn = ttk.Button(top, text="Start", command=self.start_service)
        self.start_btn.pack(side="right")
        self.pause_btn = ttk.Button(top, text="Pause…", command=self.pause_dialog)
        self.pause_btn.pack(side="right", padx=(0, 8))

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # Allowed websites tab
        allowed = ttk.Frame(self.nb, padding=10)
        self.nb.add(allowed, text="Allowed websites")
        cols = ("website", "scope")
        self.allowed_tree = ttk.Treeview(allowed, columns=cols, show="headings", selectmode="extended")
        self.allowed_tree.heading("website", text="Website")
        self.allowed_tree.heading("scope", text="Scope")
        self.allowed_tree.column("website", width=360, anchor="w")
        self.allowed_tree.column("scope", width=220, anchor="w")
        vsb = ttk.Scrollbar(allowed, orient="vertical", command=self.allowed_tree.yview)
        self.allowed_tree.configure(yscrollcommand=vsb.set)
        self.allowed_tree.grid(row=0, column=0, columnspan=4, sticky="nsew")
        vsb.grid(row=0, column=4, sticky="ns")
        allowed.rowconfigure(0, weight=1)
        allowed.columnconfigure(1, weight=1)
        ttk.Label(allowed, text="Website:").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.add_entry = ttk.Entry(allowed)
        self.add_entry.grid(row=1, column=1, sticky="we", pady=(10, 0), padx=(6, 6))
        self.add_entry.bind("<Return>", lambda e: self.add_allowed())
        self.scope_var = tk.StringVar(value="domain")
        scope = ttk.Frame(allowed)
        scope.grid(row=1, column=2, sticky="w", pady=(10, 0))
        ttk.Radiobutton(scope, text="with subdomains", variable=self.scope_var, value="domain").pack(side="left")
        ttk.Radiobutton(scope, text="exact name only", variable=self.scope_var, value="exact").pack(side="left", padx=(8, 0))
        ttk.Button(allowed, text="Add", command=self.add_allowed).grid(row=1, column=3, sticky="e", pady=(10, 0))
        ttk.Button(allowed, text="Remove selected", command=self.remove_allowed).grid(row=2, column=3, sticky="e", pady=(8, 0))

        # Blocked traffic tab
        blocked = ttk.Frame(self.nb, padding=10)
        self.nb.add(blocked, text="Blocked traffic")
        cols = ("domain", "hits", "last_seen", "last_name")
        self.blocked_tree = ttk.Treeview(blocked, columns=cols, show="headings", selectmode="extended")
        for col, text, width, anchor in (("domain", "Domain", 220, "w"), ("hits", "Hits", 60, "e"),
                                         ("last_seen", "Last seen", 150, "w"), ("last_name", "Last full hostname", 300, "w")):
            self.blocked_tree.heading(col, text=text, command=lambda c=col: self._sort_blocked(c))
            self.blocked_tree.column(col, width=width, anchor=anchor)
        vsb2 = ttk.Scrollbar(blocked, orient="vertical", command=self.blocked_tree.yview)
        self.blocked_tree.configure(yscrollcommand=vsb2.set)
        self.blocked_tree.grid(row=0, column=0, columnspan=5, sticky="nsew")
        vsb2.grid(row=0, column=5, sticky="ns")
        blocked.rowconfigure(0, weight=1)
        blocked.columnconfigure(4, weight=1)
        btns = ttk.Frame(blocked)
        btns.grid(row=1, column=0, columnspan=5, sticky="we", pady=(10, 0))
        ttk.Button(btns, text="Allow selected (domain)", command=lambda: self.allow_selected(False)).pack(side="left")
        ttk.Button(btns, text="Allow selected (exact name)", command=lambda: self.allow_selected(True)).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Refresh", command=self.refresh_blocked).pack(side="right")
        ttk.Button(btns, text="Clear log", command=self.clear_log).pack(side="right", padx=(0, 8))
        self.blocked_sort = ("last_seen", True)
        self.blocked_entries = []

        # Settings tab
        settings = ttk.Frame(self.nb, padding=16)
        self.nb.add(settings, text="Settings")
        self.log_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings, text="Log only: record blocked websites but let everything through (for testing)",
                        variable=self.log_only_var, command=self.toggle_log_only).grid(row=0, column=0, sticky="w")
        ttk.Separator(settings).grid(row=1, column=0, sticky="we", pady=14)
        ttk.Button(settings, text="Change password…", command=self.change_password).grid(row=2, column=0, sticky="w")
        ttk.Label(settings, text="The same password is used on the block page, in this manager and to uninstall.").grid(row=3, column=0, sticky="w", pady=(4, 0))
        ttk.Separator(settings).grid(row=4, column=0, sticky="we", pady=14)
        ttk.Button(settings, text="Uninstall DNSGuard…", command=self.uninstall).grid(row=5, column=0, sticky="w")
        ttk.Label(settings, text="Stops the filter, restores the previous internet settings and removes all files.").grid(row=6, column=0, sticky="w", pady=(4, 0))
        ttk.Separator(settings).grid(row=7, column=0, sticky="we", pady=14)
        ttk.Label(settings, text=f"Data folder: {DATA_DIR}\nLog: {BLOCKED_LOG}\nErrors: {ERR_LOG}", justify="left").grid(row=8, column=0, sticky="w")

        self.footer_var = tk.StringVar(value="")
        ttk.Label(self.root, textvariable=self.footer_var, foreground="#555").pack(fill="x", padx=12, pady=(0, 8))

    # -- startup / auth ----------------------------------------------------------
    def _startup(self):
        status = self.api.status()
        self._show_status(status)
        if not status:
            from tkinter import messagebox

            if messagebox.askyesno("DNSGuard", "The filter service is not running.\n\nStart it now?", parent=self.root):
                self.start_service()
                status = self.api.status()
                self._show_status(status)
            if not status:
                self.footer_var.set("Service not running. Start it to manage the allowed websites.")
                return
        if not self.login():
            self.root.destroy()
            return
        self.refresh_all()
        self.root.after(self.REFRESH_MS, self._auto_refresh)

    def login(self):
        from tkinter import messagebox

        while True:
            if self.password is None:
                pw = ask_password_dialog("DNSGuard", "Enter the DNSGuard password to open the manager.", parent=self.root)
                if pw is None:
                    return False
                self.password = pw
            try:
                data = self.api.call("login", self.password)
                self.config = data["config"]
                self._show_status(data["status"])
                return True
            except ApiError as exc:
                self.password = None
                if exc.code == 0:
                    messagebox.showerror("DNSGuard", str(exc), parent=self.root)
                    return False
                messagebox.showerror("DNSGuard", str(exc), parent=self.root)

    def _call(self, action, **kwargs):
        from tkinter import messagebox

        try:
            return self.api.call(action, self.password or "", **kwargs)
        except ApiError as exc:
            messagebox.showerror("DNSGuard", str(exc), parent=self.root)
            if exc.code == 0:
                self._show_status(None)
            return None

    # -- status -------------------------------------------------------------------
    def _show_status(self, status):
        if not status:
            self.status_var.set("Filter is NOT running")
            self.status_label.configure(foreground="#b00020")
            self.start_btn.state(["!disabled"])
            self.pause_btn.state(["disabled"])
            return
        self.start_btn.state(["disabled"])
        self.pause_btn.state(["!disabled"])
        if status.get("paused"):
            until = status.get("paused_until")
            when = "until resumed" if until == -1 else "until " + dt.datetime.fromtimestamp(until).strftime("%H:%M")
            self.status_var.set(f"Filter is PAUSED ({when})")
            self.status_label.configure(foreground="#b26a00")
            self.pause_btn.configure(text="Resume")
        elif status.get("log_only"):
            self.status_var.set("Filter running in LOG-ONLY mode (nothing is blocked)")
            self.status_label.configure(foreground="#b26a00")
            self.pause_btn.configure(text="Pause…")
        else:
            self.status_var.set("Filter is running")
            self.status_label.configure(foreground="#1b7f3b")
            self.pause_btn.configure(text="Pause…")
        self.log_only_var.set(bool(status.get("log_only")))

    def start_service(self):
        from tkinter import messagebox

        ok = start_scheduled_task()
        if not ok:
            # Standard users may not be allowed to start the task: ask for admin rights.
            relaunch_elevated(["start"])
        deadline = time.time() + 20
        while time.time() < deadline:
            status = self.api.status()
            if status:
                self._show_status(status)
                if self.password and not self.config:
                    self.login()
                    self.refresh_all()
                return
            time.sleep(0.5)
        messagebox.showerror("DNSGuard", "The filter did not start. Check dnsguard.err in the data folder.", parent=self.root)

    # -- allowed tab -----------------------------------------------------------------
    def refresh_all(self):
        self.refresh_allowed()
        self.refresh_blocked()

    def _auto_refresh(self):
        if self.password and self.api.status():
            self.refresh_blocked(quiet=True)
        self.root.after(self.REFRESH_MS, self._auto_refresh)

    def refresh_allowed(self):
        tree = self.allowed_tree
        tree.delete(*tree.get_children())
        for name in self.config.get("allow_domains", []):
            tree.insert("", "end", iid=f"d:{name}", values=(name, "with all subdomains"))
        for name in self.config.get("allow_exact", []):
            tree.insert("", "end", iid=f"e:{name}", values=(name, "exact name only"))
        self.footer_var.set(f"{len(self.config.get('allow_domains', []))} domains, {len(self.config.get('allow_exact', []))} exact names allowed.")

    def add_allowed(self):
        name = self.add_entry.get().strip()
        if not name:
            return
        data = self._call("allow", name=name, exact=(self.scope_var.get() == "exact"))
        if data:
            self.config = data["config"]
            self.add_entry.delete(0, "end")
            self.refresh_allowed()

    def remove_allowed(self):
        from tkinter import messagebox

        items = self.allowed_tree.selection()
        if not items:
            return
        if not messagebox.askyesno("DNSGuard", f"Remove {len(items)} website(s) from the allowed list?", parent=self.root):
            return
        for iid in items:
            kind, name = iid.split(":", 1)
            data = self._call("remove", name=name, exact=(kind == "e"))
            if data:
                self.config = data["config"]
        self.refresh_allowed()

    # -- blocked tab --------------------------------------------------------------------
    def refresh_blocked(self, quiet=False):
        data = self._call("blocked") if not quiet else self._quiet_call("blocked")
        if not data:
            return
        self.blocked_entries = data["entries"]
        self._render_blocked()

    def _quiet_call(self, action, **kwargs):
        try:
            return self.api.call(action, self.password or "", **kwargs)
        except ApiError:
            return None

    def _render_blocked(self):
        key, reverse = self.blocked_sort
        entries = sorted(self.blocked_entries, key=lambda e: e[key], reverse=reverse)
        tree = self.blocked_tree
        selected = set(tree.selection())
        tree.delete(*tree.get_children())
        for e in entries:
            tree.insert("", "end", iid=e["domain"], values=(e["domain"], e["hits"], e["last_seen"], e["last_name"]))
        for iid in selected:
            if tree.exists(iid):
                tree.selection_add(iid)
        total = sum(e["hits"] for e in entries)
        self.footer_var.set(f"{len(entries)} blocked domains, {total} blocked requests in the log.")

    def _sort_blocked(self, col):
        key, reverse = self.blocked_sort
        self.blocked_sort = (col, not reverse if key == col else col in ("hits", "last_seen"))
        self._render_blocked()

    def allow_selected(self, exact):
        items = self.blocked_tree.selection()
        if not items:
            return
        by_domain = {e["domain"]: e for e in self.blocked_entries}
        for iid in items:
            e = by_domain.get(iid)
            if not e:
                continue
            name = e["last_name"] if exact else e["domain"]
            data = self._call("allow", name=name, exact=exact)
            if data:
                self.config = data["config"]
        self.refresh_allowed()
        self.footer_var.set("Allowed. The blocked log keeps the old entries until you clear it.")

    def clear_log(self):
        from tkinter import messagebox

        if messagebox.askyesno("DNSGuard", "Clear the blocked traffic log?", parent=self.root):
            if self._call("clear_log") is not None:
                self.refresh_blocked()

    # -- settings tab ---------------------------------------------------------------------
    def toggle_log_only(self):
        data = self._call("set_log_only", value=self.log_only_var.get())
        if data:
            self._show_status(data["status"])
        else:
            self.log_only_var.set(not self.log_only_var.get())

    def pause_dialog(self):
        from tkinter import messagebox

        status = self.api.status()
        if status and status.get("paused"):
            data = self._call("resume")
            if data:
                self._show_status(data["status"])
            return
        dlg = self.tk.Toplevel(self.root)
        dlg.title("Pause filter")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        frame = self.ttk.Frame(dlg, padding=16)
        frame.pack()
        self.ttk.Label(frame, text="Let all websites through for:").pack(anchor="w", pady=(0, 8))

        def pick(minutes):
            dlg.destroy()
            data = self._call("pause", minutes=minutes)
            if data:
                self._show_status(data["status"])
                messagebox.showinfo("DNSGuard", "Filter paused. Nothing is blocked until it resumes.", parent=self.root)

        for text, minutes in (("15 minutes", 15), ("1 hour", 60), ("4 hours", 240), ("Until I resume it", 0)):
            self.ttk.Button(frame, text=text, width=24, command=lambda m=minutes: pick(m)).pack(fill="x", pady=2)
        self.ttk.Button(frame, text="Cancel", width=24, command=dlg.destroy).pack(fill="x", pady=(10, 0))

    def change_password(self):
        from tkinter import messagebox

        new = ask_password_dialog("Change password", "Choose a new DNSGuard password (at least 6 characters).",
                                  confirm=True, parent=self.root)
        if new is None:
            return
        data = self._call("change_password", new_password=new)
        if data:
            self.password = new
            messagebox.showinfo("DNSGuard", "Password changed.", parent=self.root)

    def uninstall(self):
        from tkinter import messagebox

        if not messagebox.askyesno("Uninstall DNSGuard",
                                   "This stops the filter, restores the previous internet settings and removes DNSGuard.\n\nContinue?",
                                   icon="warning", parent=self.root):
            return
        pw = ask_password_dialog("Uninstall DNSGuard", "Enter the DNSGuard password to confirm the uninstall.", parent=self.root)
        if pw is None:
            return
        try:
            data = self.api.call("uninstall", pw)
        except ApiError as exc:
            messagebox.showerror("DNSGuard", str(exc), parent=self.root)
            return
        messagebox.showinfo("DNSGuard", data.get("message", "Uninstalling."), parent=self.root)
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_install(args):
    if not IS_WINDOWS:
        sys.exit("DNSGuard installs on Windows only.")
    if not is_admin():
        if not relaunch_elevated(sys.argv[1:] if sys.argv[1:] else ["install"]):
            say("Administrator rights are required to install DNSGuard.", error=True)
        return
    password = args.password
    if password is None:
        if is_installed():
            # Re-install / repair keeps the existing password.
            password = ""
        else:
            password = ask_password_dialog(
                "Install DNSGuard",
                "Choose the DNSGuard password. You will need it to allow websites, open the manager and uninstall.",
                confirm=True)
            if password is None:
                return
    else:
        problem = password_problem(password)
        if problem and not is_installed():
            sys.exit(problem)
    for port, udp in ((53, True), (80, False), (443, False)):
        if port_in_use(port, udp=udp) and not ApiClient().status():
            say(f"Port {port} is already in use by another program on 127.0.0.1. DNSGuard needs it.", error=True)
            return
    extra = [x for x in (args.allow or "").split(",") if x.strip()]
    steps = []
    try:
        install_core(password, extra_allow=extra, log_only=args.log_only, progress=lambda m: steps.append(m) or (print(m) if has_console() else None))
    except Exception as exc:
        log_err("install failed", exc)
        say(f"Installation failed: {exc}\n\nDetails are in {ERR_LOG}", error=True)
        return
    say("DNSGuard is installed and running.\n\nAll websites are blocked except the allowed ones. "
        "Open 'DNSGuard Manager' from the Start menu to manage the list.")


def cmd_run(args):
    if args.dns_port != 53 or args.http_port != 80 or args.https_port != 443:
        os.environ.setdefault("DNSGUARD_HTTP_PORT", str(args.http_port))
    service = Service(dns_port=args.dns_port, http_port=args.http_port, https_port=args.https_port,
                      manage_dns=not args.no_dns)
    if args.password:
        # Development convenience: create/overwrite the config password without installing.
        cfg = Config()
        if CONFIG_FILE.exists():
            cfg.load()
        cfg.data["password"] = hash_password(args.password)
        cfg.data["created"] = cfg.data.get("created") or now_iso()
        cfg.save()
    if not CONFIG_FILE.exists():
        log_err("no config.json: run install first")
        sys.exit("No configuration found. Run 'install' first.")
    try:
        service.start()
    except Exception as exc:
        log_err("service start failed", exc)
        raise
    if has_console():
        print(f"DNSGuard {VERSION} running: DNS {service.dns_port}, HTTP {service.http_port}, HTTPS {service.https_port}. Ctrl+C to stop.")
    try:
        service.serve_forever()
    except KeyboardInterrupt:
        service.stop()


def cmd_manage(args):
    ManagerApp(password=args.password).run()


def cmd_uninstall(args):
    if not IS_WINDOWS:
        sys.exit("Windows only.")
    if not is_installed() and not task_exists():
        say("DNSGuard is not installed on this computer.")
        return
    password = args.password
    if password is None:
        password = ask_password_dialog("Uninstall DNSGuard", "Enter the DNSGuard password to uninstall.")
        if password is None:
            return
    # Preferred path: ask the running service (it has admin rights) to uninstall itself.
    api = ApiClient()
    if api.status():
        try:
            api.call("uninstall", password)
        except ApiError as exc:
            if exc.code != 0:
                say(str(exc), error=True)
                return
        else:
            _wait_for_uninstall()
            say("DNSGuard was removed and the previous internet settings were restored.")
            return
    # Service not running: do it ourselves with admin rights.
    if not is_admin():
        if not relaunch_elevated(["uninstall", "--password", password]):
            say("Administrator rights are required.", error=True)
        return
    try:
        cfg = Config().load()
        if not cfg.check_password(password):
            say("Wrong password.", error=True)
            return
    except Exception:
        pass  # config missing or unreadable: allow cleanup of a broken install
    uninstall_core(stop_service=True)
    if FROZEN and Path(sys.executable).resolve() == INSTALLED_EXE.resolve():
        schedule_self_cleanup()
    else:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
    say("DNSGuard was removed and the previous internet settings were restored.")


def _wait_for_uninstall(timeout=60):
    deadline = time.time() + timeout
    api = ApiClient()
    while time.time() < deadline:
        if not api.status() and not INSTALL_MARKER.exists():
            return True
        time.sleep(1)
    return False


def _password_for_cli(args, prompt):
    if args.password is not None:
        return args.password
    if has_console():
        import getpass

        return getpass.getpass(prompt + ": ")
    return ask_password_dialog(APP_NAME, prompt)


def cmd_pause(args):
    pw = _password_for_cli(args, "DNSGuard password")
    if pw is None:
        return
    try:
        ApiClient().call("pause", pw, minutes=args.minutes)
    except ApiError as exc:
        say(str(exc), error=True)
        return
    say("Filter paused " + ("until resumed." if args.minutes <= 0 else f"for {args.minutes} minutes."))


def cmd_resume(args):
    pw = _password_for_cli(args, "DNSGuard password")
    if pw is None:
        return
    try:
        ApiClient().call("resume", pw)
    except ApiError as exc:
        say(str(exc), error=True)
        return
    say("Filter resumed.")


def cmd_status(args):
    status = ApiClient().status()
    if not status:
        say("DNSGuard filter: NOT running" + (" (installed)" if is_installed() else " (not installed)"))
        return 1
    state = "PAUSED" if status["paused"] else ("LOG-ONLY" if status["log_only"] else "ACTIVE")
    say(f"DNSGuard {status['version']}: {state}\n"
        f"installed: {status['installed']}, uptime: {status['uptime']} s, "
        f"blocked since start: {status['blocked_since_start']}\n"
        f"ports: dns {status['ports']['dns']}, http {status['ports']['http']}, https {status['ports']['https']}")
    return 0


def cmd_allow(args):
    pw = _password_for_cli(args, "DNSGuard password")
    if pw is None:
        return
    try:
        data = ApiClient().call("allow", pw, name=args.domain, exact=args.exact)
    except ApiError as exc:
        say(str(exc), error=True)
        return 1
    say(f"Allowed {data['name']}" + (" (exact name)" if args.exact else " (with subdomains)"))


def cmd_start(args):
    if not is_installed():
        say("DNSGuard is not installed.", error=True)
        return
    if ApiClient().status():
        say("The filter is already running.")
        return
    if not start_scheduled_task():
        if not is_admin():
            relaunch_elevated(["start"])
            return
        say("Could not start the DNSGuard task.", error=True)
        return
    deadline = time.time() + 20
    while time.time() < deadline:
        if ApiClient().status():
            say("Filter started.")
            return
        time.sleep(0.5)
    say("The filter did not start. Check dnsguard.err.", error=True)


def cmd_logon(args):
    """Run at each sign-in by the logon task, as the signed-in user."""
    if not IS_WINDOWS:
        return
    try:
        set_desktop_wallpaper()
    except Exception as exc:
        log_err("set wallpaper failed", exc)
    if not args.no_browser:
        try:
            os.startfile("microsoft-edge:" + START_PAGE_URL)
        except OSError as exc:
            log_err("open start page failed", exc)


def build_parser():
    p = argparse.ArgumentParser(prog=APP_NAME, description="DNSGuard whitelist web filter")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    p.add_argument("-q", "--quiet", action="store_true", help="no message boxes (for scripts)")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("install", help="install on this computer")
    s.add_argument("--password", help="set the password without asking (6+ characters)")
    s.add_argument("--allow", help="comma-separated extra domains to allow")
    s.add_argument("--log-only", action="store_true", help="start in log-only mode (nothing blocked)")

    s = sub.add_parser("run", help="run the filter service")
    s.add_argument("--dns-port", type=int, default=53)
    s.add_argument("--http-port", type=int, default=80)
    s.add_argument("--https-port", type=int, default=443)
    s.add_argument("--no-dns", action="store_true", help="do not touch the network adapters' DNS settings")
    s.add_argument("--password", help="(development) set the config password before starting")

    s = sub.add_parser("manage", help="open the manager window")
    s.add_argument("--password")

    s = sub.add_parser("uninstall", help="remove DNSGuard")
    s.add_argument("--password")

    s = sub.add_parser("pause", help="pause filtering")
    s.add_argument("--minutes", type=int, default=30, help="0 = until resumed (default 30)")
    s.add_argument("--password")

    s = sub.add_parser("resume", help="resume filtering")
    s.add_argument("--password")

    sub.add_parser("status", help="show filter status")

    s = sub.add_parser("allow", help="allow a website")
    s.add_argument("domain")
    s.add_argument("--exact", action="store_true", help="allow only this exact name, not subdomains")
    s.add_argument("--password")

    sub.add_parser("start", help="start the filter service")

    s = sub.add_parser("logon", help="set the desktop picture and open the start page")
    s.add_argument("--no-browser", action="store_true", help="only set the desktop picture")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    global QUIET
    QUIET = bool(args.quiet)
    if args.command is None:
        if is_installed():
            args = parser.parse_args(["manage"])
        else:
            args = parser.parse_args(["install"])
    handlers = {
        "install": cmd_install, "run": cmd_run, "manage": cmd_manage, "uninstall": cmd_uninstall,
        "pause": cmd_pause, "resume": cmd_resume, "status": cmd_status, "allow": cmd_allow, "start": cmd_start,
        "logon": cmd_logon,
    }
    try:
        return handlers[args.command](args) or 0
    except SystemExit:
        raise
    except Exception as exc:
        log_err(f"command {args.command} crashed", exc)
        say(f"{type(exc).__name__}: {exc}\n\nDetails: {ERR_LOG}", error=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
