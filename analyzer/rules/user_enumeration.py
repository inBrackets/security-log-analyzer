from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterator

from .base import BaseRule
from analyzer.models import AuthEntry, Incident, LogEntry, Severity


class UserEnumerationRule(BaseRule):
    """
    Detects probing of non-existent SSH usernames from a single IP.
    sshd logs these as "Failed password for invalid user <name>".
    """

    name = "user_enumeration"

    def __init__(self, threshold: int = 2, window_seconds: int = 60) -> None:
        self._threshold = threshold
        self._window = window_seconds
        # ip → deque of (timestamp, username, raw_line)
        self._attempts: dict[str, deque] = defaultdict(deque)
        self._alerted: set[str] = set()

    def feed(self, entry: LogEntry) -> Iterator[Incident]:
        if not isinstance(entry, AuthEntry) or not entry.is_invalid_user:
            return
        if not entry.source_ip or not entry.timestamp:
            return

        ip = entry.source_ip
        buf = self._attempts[ip]
        buf.append((entry.timestamp, entry.username or "?", entry.raw))
        self._evict(buf, entry.timestamp, self._window)

        if len(buf) >= self._threshold and ip not in self._alerted:
            self._alerted.add(ip)
            usernames = list(dict.fromkeys(e[1] for e in buf))
            yield Incident(
                rule_name=self.name,
                severity=Severity.MEDIUM,
                source_ip=ip,
                description=f"SSH user enumeration: probed usernames {usernames}",
                evidence=[e[2] for e in buf],
                first_seen=buf[0][0],
                last_seen=entry.timestamp,
                count=len(buf),
            )

