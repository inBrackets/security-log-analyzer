from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterator
from datetime import datetime

from .base import BaseRule
from .ip_tracker import IPEvent, IPTracker
from analyzer.models import Incident, LogEntry, Severity, WebEntry

_LOGIN_PATHS = {"/login", "/signin", "/auth", "/session", "/wp-login.php"}


class WebBruteForceRule(BaseRule):
    """
    Detects repeated HTTP 401 failures on login endpoints (HIGH), escalates
    to CRITICAL when a successful POST follows from the same IP.

    Cross-protocol correlation
    --------------------------
    When an optional IPTracker is provided, every failure and success event is
    recorded there so that CrossProtocolBruteForceRule can correlate web
    activity with SSH-layer attacks from the same IP.
    """

    name = "web_brute_force"

    def __init__(
        self,
        threshold: int = 3,
        window_seconds: int = 60,
        tracker: IPTracker | None = None,
    ) -> None:
        self._threshold = threshold
        self._window = window_seconds
        self._tracker = tracker
        # ip → deque of (timestamp, raw_line)
        self._failures: dict[str, deque] = defaultdict(deque)
        self._alerted: set[str] = set()

    def feed(self, entry: LogEntry) -> Iterator[Incident]:
        if not isinstance(entry, WebEntry) or not entry.source_ip or not entry.timestamp:
            return
        if not self._is_login(entry.path):
            return

        ip = entry.source_ip

        if entry.status_code == 401:
            yield from self._handle_failure(entry, ip)

        elif entry.status_code == 200 and entry.method == "POST":
            yield from self._handle_success(entry, ip)

    # ------------------------------------------------------------------

    def _handle_failure(self, entry: WebEntry, ip: str) -> Iterator[Incident]:
        buf = self._failures[ip]
        buf.append((entry.timestamp, entry.raw))
        self._evict(buf, entry.timestamp)

        if self._tracker:
            self._tracker.record(ip, IPEvent(
                timestamp=entry.timestamp,
                protocol="web",
                event_type="failure",
                detail=f"401 {entry.method} {entry.path}",
            ))

        if len(buf) >= self._threshold and ip not in self._alerted:
            self._alerted.add(ip)
            yield Incident(
                rule_name=self.name,
                severity=Severity.HIGH,
                source_ip=ip,
                description=(
                    f"Web brute force: {len(buf)} failed logins in "
                    f"{self._window}s against '{entry.path}'"
                ),
                evidence=[e[1] for e in buf],
                first_seen=buf[0][0],
                last_seen=entry.timestamp,
                count=len(buf),
            )

    def _handle_success(self, entry: WebEntry, ip: str) -> Iterator[Incident]:
        if self._tracker:
            self._tracker.record(ip, IPEvent(
                timestamp=entry.timestamp,
                protocol="web",
                event_type="success",
                detail=f"200 POST {entry.path}",
            ))

        buf = self._failures.get(ip)
        if not buf:
            return

        count    = len(buf)
        evidence = [e[1] for e in buf] + [entry.raw]
        first    = buf[0][0]
        self._failures[ip] = deque()
        self._alerted.discard(ip)

        yield Incident(
            rule_name=self.name,
            severity=Severity.CRITICAL,
            source_ip=ip,
            description=(
                f"Web brute force SUCCEEDED: {count} failures then "
                f"successful POST to '{entry.path}'"
            ),
            evidence=evidence,
            first_seen=first,
            last_seen=entry.timestamp,
            count=count + 1,
        )

    def _is_login(self, path: str) -> bool:
        return path in _LOGIN_PATHS or any(p in path for p in _LOGIN_PATHS)

    def _evict(self, buf: deque, current: datetime) -> None:
        while buf and (current - buf[0][0]).total_seconds() > self._window:
            buf.popleft()
