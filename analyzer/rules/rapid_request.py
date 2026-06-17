from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterator

from .base import BaseRule
from analyzer.models import Incident, LogEntry, Severity, WebEntry


class RapidRequestRule(BaseRule):
    """
    Detects a burst of identical POST requests from a single IP to the same
    endpoint within a very tight time window.

    Legitimate users rarely submit the same form or call the same API endpoint
    more than a handful of times per second.  A rapid burst is a strong signal
    of automation: credential stuffing, payment fraud, inventory manipulation,
    or aggressive scraping.

    HTTP 429 (Too Many Requests) responses from an upstream rate-limiter appear
    naturally in the evidence alongside the original requests, making the abuse
    pattern and the gateway's reaction visible in a single incident.

    Deduplication is keyed on (IP, path), so the same IP abusing two different
    endpoints produces two independent incidents.
    """

    name = "rapid_request"

    def __init__(self, threshold: int = 5, window_seconds: float = 2.0) -> None:
        self._threshold = threshold
        self._window = window_seconds
        # (ip, path) → deque of (timestamp, raw_line)
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self._alerted: set[tuple[str, str]] = set()

    def feed(self, entry: LogEntry) -> Iterator[Incident]:
        if not isinstance(entry, WebEntry) or not entry.source_ip or not entry.timestamp:
            return
        if entry.method != "POST":
            return

        ip = entry.source_ip
        key = (ip, entry.path)
        if key in self._alerted:
            return

        buf = self._hits[key]
        buf.append((entry.timestamp, entry.raw))
        self._evict(buf, entry.timestamp, self._window)

        n = len(buf)
        if n > self._threshold:
            self._alerted.add(key)
            yield Incident(
                rule_name=self.name,
                severity=Severity.HIGH,
                source_ip=ip,
                description=(
                    f"Rapid requests: {ip} sent {n} POST requests to "
                    f"'{entry.path}' within {self._window}s"
                ),
                evidence=[e[1] for e in buf],
                first_seen=buf[0][0],
                last_seen=entry.timestamp,
                count=n,
            )
