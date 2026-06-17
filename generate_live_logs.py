#!/usr/bin/env python3
"""
generate_live_logs.py -- Live log generator for the security log analyzer.

Streams auth.log and webserver.log into logs-live/ with real-time timestamps
and coherent multi-stage attack narratives.  Each scenario uses a consistent
attacker IP across both log files so cross-protocol detection works.

Usage:
    python generate_live_logs.py [--speed N]

    --speed N   Run N times faster (timestamps still track wall-clock so
                detection windows stay valid).  Default: 1.  Use --speed 10
                to see all scenarios trigger within a few minutes.

Analyze any time while the generator is running:
    python -m analyzer.cli --log-dir logs-live --output narrative
"""

from __future__ import annotations

import argparse
import heapq
import random
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------

_OUT  = Path("logs-live")
_AUTH = _OUT / "auth.log"
_WEB  = _OUT / "webserver.log"
_HOST = "server"

# ---------------------------------------------------------------------------
# Timestamp formatters
# ---------------------------------------------------------------------------

_MONTHS = ["Jan","Feb","Mar","Apr","May","Jun",
           "Jul","Aug","Sep","Oct","Nov","Dec"]

def _auth_ts(dt: datetime) -> str:
    return f"{_MONTHS[dt.month - 1]} {dt.day:2d} {dt.strftime('%H:%M:%S')}"

def _web_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

# ---------------------------------------------------------------------------
# IP / data pools
# ---------------------------------------------------------------------------

_ATTACKER_IPS = [
    "45.33.32.156",   "185.220.101.47", "109.201.133.195",
    "194.165.16.78",  "91.108.4.0",     "23.129.64.213",
    "198.98.56.148",  "104.244.76.13",  "176.10.104.240",
]

_BENIGN_IPS = [
    "10.0.0.5", "10.0.0.12", "10.0.0.33",
    "172.16.1.4", "192.168.10.20",
]

_INVALID_USERS = [
    "admin", "root", "ubuntu", "pi", "postgres", "git", "deploy",
    "test", "oracle", "backup", "ftp", "nagios", "jenkins", "redis",
    "hadoop", "elastic", "ansible",
]

_VALID_USERS = ["alice", "bob", "carol", "dave"]

_SCAN_PATHS = [
    "/admin", "/.env", "/config.php", "/wp-admin/", "/phpmyadmin/",
    "/.git/config", "/backup.zip", "/server-status", "/actuator/health",
    "/api/v1/users", "/.htaccess", "/xmlrpc.php", "/shell.php",
    "/manager/html", "/.DS_Store", "/web.config", "/setup.php",
    "/debug/", "/console", "/adminer.php", "/cgi-bin/test.cgi",
    "/old/admin.php", "/install.php",
]

_SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' UNION SELECT username,password FROM users--",
    "1 OR 1=1",
    "admin'--",
    "' OR 1=1 LIMIT 1--",
]

_TRAVERSAL_PATHS = [
    "/files/../../../etc/passwd",
    "/download?file=../../etc/shadow",
    "/images/../../../../.ssh/id_rsa",
    "/static/%2e%2e%2fetc/passwd",
]

_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "python-requests/2.28.1",
    "curl/7.81.0",
    "Nikto/2.1.6",
    "sqlmap/1.7.2",
]

_API_ENDPOINTS = ["/api/checkout", "/api/payment", "/api/transfer"]

# ---------------------------------------------------------------------------
# Primitive line builders
# Each returns a zero-argument callable that captures the real timestamp at
# call time (fire time), not at schedule time.
# ---------------------------------------------------------------------------

def _rand_port() -> int:
    return random.randint(49152, 65535)

def _rand_size(lo: int = 256, hi: int = 8192) -> int:
    return random.randint(lo, hi)

def _rand_pid() -> int:
    return random.randint(1000, 59999)

# Return type convention: ("auth"|"web", log_line_string)

def _ssh_failed(ip: str, pid: int, user: str, port: int, invalid: bool = True):
    inv = "invalid user " if invalid else ""
    def _w():
        ts = _auth_ts(datetime.now())
        return "auth", f"{ts} {_HOST} sshd[{pid}]: Failed password for {inv}{user} from {ip} port {port} ssh2"
    return _w

def _ssh_accepted(ip: str, pid: int, user: str, port: int):
    def _w():
        ts = _auth_ts(datetime.now())
        return "auth", f"{ts} {_HOST} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"
    return _w

def _ssh_closed(ip: str, pid: int, port: int):
    def _w():
        ts = _auth_ts(datetime.now())
        return "auth", f"{ts} {_HOST} sshd[{pid}]: Connection closed by {ip} port {port}"
    return _w

def _sudo(user: str, cmd: str):
    def _w():
        ts = _auth_ts(datetime.now())
        return "auth", f"{ts} {_HOST} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
    return _w

def _web(ip: str, method: str, path: str, status: int, ua: str, size: int | None = None):
    def _w():
        ts = _web_ts(datetime.now())
        sz = size if size is not None else _rand_size()
        return "web", f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {sz} "-" "{ua}"'
    return _w

# ---------------------------------------------------------------------------
# Scenario factories
#
# Each returns list[(delay_seconds, writer_callable)].
# Delays are relative to the moment the scenario starts.
# All delays are divided by `speed` so the scenario runs faster at speed > 1.
# ---------------------------------------------------------------------------

def scen_ssh_brute(speed: float) -> list:
    """SSH brute force: many failed logins from one IP."""
    ip  = random.choice(_ATTACKER_IPS)
    pid = _rand_pid()
    n   = random.randint(22, 32)
    return [
        ((i * random.uniform(1.0, 2.5)) / speed,
         _ssh_failed(ip, pid, _INVALID_USERS[i % len(_INVALID_USERS)], _rand_port()))
        for i in range(n)
    ]


def scen_ssh_privesc(speed: float) -> list:
    """SSH brute force -> successful login -> sudo to sensitive files."""
    ip   = random.choice(_ATTACKER_IPS)
    pid  = _rand_pid()
    user = random.choice(_VALID_USERS)
    n    = random.randint(18, 26)

    events = [
        ((i * random.uniform(1.0, 2.0)) / speed,
         _ssh_failed(ip, pid, _INVALID_USERS[i % len(_INVALID_USERS)], _rand_port()))
        for i in range(n)
    ]
    t_login = (n * 1.5 + random.uniform(2, 5)) / speed
    events.append((t_login, _ssh_accepted(ip, pid, user, _rand_port())))

    for j, cmd in enumerate([
        "/bin/cat /etc/shadow",
        "/bin/cat /etc/passwd",
        "/usr/bin/id",
    ]):
        events.append((t_login + (j + 1) * (4.0 / speed), _sudo(user, cmd)))

    return events


def scen_web_scanner(speed: float) -> list:
    """Recon sweep: many distinct 403/404 paths from one IP."""
    ip    = random.choice(_ATTACKER_IPS)
    ua    = random.choice(_UAS[1:])
    paths = random.sample(_SCAN_PATHS, min(14, len(_SCAN_PATHS)))
    return [
        ((i * random.uniform(3.0, 6.0)) / speed,
         _web(ip, "GET", path, random.choice([403, 404, 404]), ua))
        for i, path in enumerate(paths)
    ]


def scen_web_brute(speed: float) -> list:
    """Web brute force: repeated POST /login failures then a success."""
    ip = random.choice(_ATTACKER_IPS)
    ua = _UAS[0]
    n  = random.randint(20, 30)
    events = [
        ((i * random.uniform(1.5, 3.0)) / speed,
         _web(ip, "POST", "/login", 401, ua))
        for i in range(n)
    ]
    events.append(((n * 2.0 + 3) / speed, _web(ip, "POST", "/login", 200, ua)))
    return events


def scen_sql_injection(speed: float) -> list:
    """SQL injection probes escalating to UNION-based extraction."""
    ip = random.choice(_ATTACKER_IPS)
    ua = "sqlmap/1.7.2"
    events = [(0.0, _web(ip, "GET", "/search?q=test", 200, ua))]
    for i, payload in enumerate(_SQL_PAYLOADS):
        delay  = ((i + 1) * random.uniform(0.5, 1.5)) / speed
        status = random.choice([200, 500])
        events.append((delay, _web(ip, "GET", f"/search?q={payload}", status, ua)))
    return events


def scen_user_enum(speed: float) -> list:
    """User enumeration: many distinct invalid usernames via SSH."""
    ip    = random.choice(_ATTACKER_IPS)
    pid   = _rand_pid()
    users = random.sample(_INVALID_USERS, min(10, len(_INVALID_USERS)))
    return [
        ((i * random.uniform(2.0, 5.0)) / speed,
         _ssh_failed(ip, pid, u, _rand_port()))
        for i, u in enumerate(users)
    ]


def scen_cross_protocol(speed: float) -> list:
    """Same IP bruteforces SSH then switches to web login -- fires CrossProtocol rule."""
    ip  = random.choice(_ATTACKER_IPS)
    pid = _rand_pid()
    ua  = _UAS[0]

    events = [
        ((i * random.uniform(1.5, 3.0)) / speed,
         _ssh_failed(ip, pid, "root", _rand_port(), invalid=False))
        for i in range(6)
    ]
    web_base = (6 * 2.5 + random.uniform(5, 15)) / speed
    for i in range(6):
        delay = web_base + (i * random.uniform(1.5, 3.0)) / speed
        events.append((delay, _web(ip, "POST", "/login", 401, ua)))
    return events


def scen_rapid_requests(speed: float) -> list:
    """Burst of identical POST requests to the same API endpoint."""
    ip = random.choice(_ATTACKER_IPS)
    ep = random.choice(_API_ENDPOINTS)
    ua = _UAS[0]
    n  = random.randint(8, 12)
    return [
        ((i * 0.25) / speed,
         _web(ip, "POST", ep, 200 if i < 2 else 429, ua, 89))
        for i in range(n)
    ]


def scen_path_traversal(speed: float) -> list:
    """Directory traversal attempts targeting sensitive files."""
    ip = random.choice(_ATTACKER_IPS)
    ua = random.choice(_UAS[1:3])
    return [
        ((i * random.uniform(1.0, 3.0)) / speed,
         _web(ip, "GET", path, 403, ua))
        for i, path in enumerate(_TRAVERSAL_PATHS)
    ]


def scen_benign_web(speed: float) -> list:
    """Normal authenticated browsing session."""
    ip    = random.choice(_BENIGN_IPS)
    ua    = _UAS[0]
    paths = random.sample(
        ["/", "/index.html", "/about", "/products", "/contact", "/api/status"],
        random.randint(2, 5),
    )
    delay = 0.0
    events = []
    for path in paths:
        events.append((delay, _web(ip, "GET", path, 200, ua)))
        delay += random.uniform(1.0, 5.0) / speed
    return events


def scen_benign_ssh(speed: float) -> list:
    """Normal SSH login and logout."""
    ip   = random.choice(_BENIGN_IPS)
    user = random.choice(_VALID_USERS)
    pid  = _rand_pid()
    port = _rand_port()
    return [
        (0.0,                                      _ssh_accepted(ip, pid, user, port)),
        (random.uniform(30, 120) / speed,          _ssh_closed(ip, pid, port)),
    ]


# ---------------------------------------------------------------------------
# Scenario registry: (factory, interval_seconds, display_label)
# interval_seconds: real-time gap between consecutive runs of this scenario
# ---------------------------------------------------------------------------

_REGISTRY = [
    (scen_ssh_brute,      120, "SSH Brute Force"),
    (scen_ssh_privesc,    300, "SSH Privesc + Sudo"),
    (scen_web_scanner,     90, "Web Scanner"),
    (scen_web_brute,      180, "Web Brute Force"),
    (scen_sql_injection,  200, "SQL Injection"),
    (scen_user_enum,      220, "User Enumeration"),
    (scen_cross_protocol, 260, "Cross-Protocol Attack"),
    (scen_rapid_requests,  60, "Rapid API Abuse"),
    (scen_path_traversal, 130, "Path Traversal"),
    (scen_benign_web,      18, "Benign Web Traffic"),
    (scen_benign_ssh,      45, "Benign SSH Session"),
]

# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

class _Scheduler:
    def __init__(self) -> None:
        self._heap: list = []   # (fire_at, seq, writer)
        self._seq  = 0
        self._auth_fh = None
        self._web_fh  = None

    def open(self) -> None:
        _OUT.mkdir(parents=True, exist_ok=True)
        self._auth_fh = open(_AUTH, "a", encoding="utf-8", buffering=1)
        self._web_fh  = open(_WEB,  "a", encoding="utf-8", buffering=1)

    def close(self) -> None:
        for fh in (self._auth_fh, self._web_fh):
            if fh:
                fh.close()

    def enqueue(self, delay: float, writer) -> None:
        heapq.heappush(self._heap, (time.monotonic() + delay, self._seq, writer))
        self._seq += 1

    def load(self, events: list) -> None:
        for delay, writer in events:
            self.enqueue(delay, writer)

    def fire_due(self) -> None:
        now = time.monotonic()
        while self._heap and self._heap[0][0] <= now:
            _, _, writer = heapq.heappop(self._heap)
            target, line = writer()
            fh = self._auth_fh if target == "auth" else self._web_fh
            fh.write(line + "\n")
            tag = "AUTH" if target == "auth" else "WEB "
            print(f"  [{tag}] {line[:115]}")

    def next_fire_at(self) -> float | None:
        return self._heap[0][0] if self._heap else None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate live security logs for the analyzer.",
        epilog=(
            "Analyze while running:\n"
            "  python -m analyzer.cli --log-dir logs-live --output narrative"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--speed", type=float, default=1.0, metavar="N",
        help="Event frequency multiplier. Default: 1. Use 10 for a rapid demo.",
    )
    args = ap.parse_args()
    speed = max(0.1, args.speed)

    sched = _Scheduler()
    sched.open()

    print(f"Writing to  {_OUT.resolve()}")
    print(f"  {_AUTH.name}  and  {_WEB.name}")
    print(f"  speed {speed}x    (Ctrl+C to stop)\n")
    print("Run the analyzer at any time:")
    print(f"  python -m analyzer.cli --log-dir {_OUT} --output narrative\n")

    # Scenario heap: (fire_at, seq, factory, adjusted_interval, label)
    # seq as tiebreaker keeps factory (not comparable) from being used in <
    seq = 0
    scen_heap: list = []
    stagger = 0.0
    t0 = time.monotonic()

    for factory, interval, label in _REGISTRY:
        heapq.heappush(scen_heap, (t0 + stagger, seq, factory, interval / speed, label))
        seq += 1
        stagger += random.uniform(1.5, 5.0) / speed

    try:
        while True:
            now = time.monotonic()

            # Launch any scenarios that are due
            while scen_heap and scen_heap[0][0] <= now:
                _, _, factory, interval, label = heapq.heappop(scen_heap)
                print(f"\n>>> {label}")
                sched.load(factory(speed=speed))
                next_at = now + interval * random.uniform(0.85, 1.15)
                heapq.heappush(scen_heap, (next_at, seq, factory, interval, label))
                seq += 1

            # Write any log lines whose time has come
            sched.fire_due()

            # Sleep until the nearest upcoming event
            candidates = []
            if scen_heap:
                candidates.append(scen_heap[0][0])
            nf = sched.next_fire_at()
            if nf is not None:
                candidates.append(nf)
            sleep_s = max(0.001, min(candidates) - time.monotonic()) if candidates else 0.05
            time.sleep(min(sleep_s, 0.1))

    except KeyboardInterrupt:
        sched.close()
        print("\n\nStopped.  Analyze the captured logs:")
        print(f"  python -m analyzer.cli --log-dir {_OUT} --output narrative")
        sys.exit(0)


if __name__ == "__main__":
    _main()
