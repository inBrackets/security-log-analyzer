from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterator
from datetime import datetime

from .base import BaseRule
from .ip_tracker import IPEvent, IPTracker
from analyzer.models import AuthEntry, Incident, LogEntry, Severity


class SSHBruteForceRule(BaseRule):
    """
    Detects rapid SSH password failures from a single IP (HIGH), escalates to
    CRITICAL when a subsequent login from that IP succeeds.

    Cross-protocol correlation
    --------------------------
    When an optional IPTracker is provided, every failure and success event is
    recorded there so that CrossProtocolBruteForceRule can correlate SSH
    activity with web-layer attacks from the same IP.
    """

    name = "ssh_brute_force"

    def __init__(
        self,
        threshold: int = 3,
        window_seconds: int = 60,
        tracker: IPTracker | None = None,
    ) -> None:
        self._threshold = threshold
        self._window = window_seconds
        self._tracker = tracker
        # ip → deque of (timestamp, username, raw_line)
        self._failures: dict[str, deque] = defaultdict(deque)
        self._alerted: set[str] = set()

    def feed(self, entry: LogEntry) -> Iterator[Incident]:
        if not isinstance(entry, AuthEntry) or not entry.source_ip or not entry.timestamp:
            return

        ip = entry.source_ip

        if entry.event_type == "failed_password":
            yield from self._handle_failure(entry, ip)

        elif entry.event_type == "accepted_password":
            yield from self._handle_success(entry, ip)

    # ------------------------------------------------------------------

    def _handle_failure(self, entry: AuthEntry, ip: str) -> Iterator[Incident]:
        buf = self._failures[ip]
        buf.append((entry.timestamp, entry.username, entry.raw))
        self._evict(buf, entry.timestamp)

        if self._tracker:
            self._tracker.record(ip, IPEvent(
                timestamp=entry.timestamp,
                protocol="ssh",
                event_type="failure",
                detail=f"Failed password for {entry.username!r} (port {entry.port})",
            ))

        if len(buf) >= self._threshold and ip not in self._alerted:
            self._alerted.add(ip)
            yield Incident(
                rule_name=self.name,
                severity=Severity.HIGH,
                source_ip=ip,
                description=(
                    f"SSH brute force: {len(buf)} failed attempts in "
                    f"{self._window}s for user '{entry.username}'"
                ),
                evidence=[e[2] for e in buf],
                first_seen=buf[0][0],
                last_seen=entry.timestamp,
                count=len(buf),
            )

    def _handle_success(self, entry: AuthEntry, ip: str) -> Iterator[Incident]:
        if self._tracker:
            self._tracker.record(ip, IPEvent(
                timestamp=entry.timestamp,
                protocol="ssh",
                event_type="success",
                detail=f"Accepted login for {entry.username!r}",
            ))

        buf = self._failures.get(ip)
        if not buf:
            return

        count    = len(buf)
        evidence = [e[2] for e in buf] + [entry.raw]
        first    = buf[0][0]
        self._failures[ip] = deque()
        self._alerted.discard(ip)

        yield Incident(
            rule_name=self.name,
            severity=Severity.CRITICAL,
            source_ip=ip,
            description=(
                f"SSH brute force SUCCEEDED: {count} failures then "
                f"accepted login for '{entry.username}'"
            ),
            evidence=evidence,
            first_seen=first,
            last_seen=entry.timestamp,
            count=count + 1,
        )

    def _evict(self, buf: deque, current: datetime) -> None:
        while buf and (current - buf[0][0]).total_seconds() > self._window:
            buf.popleft()
