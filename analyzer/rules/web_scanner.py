from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterator

from .base import BaseRule
from analyzer.models import Incident, LogEntry, Severity, WebEntry


class WebScannerRule(BaseRule):
    """
    Detects automated path-scanning by a single IP.

    A scanner probes many distinct URLs in quick succession looking for
    exposed endpoints, admin panels, or vulnerable paths.  Individual 403/404
    responses are noise; a burst of them against *different* paths from the
    same IP is a strong recon signal.

    The rule counts distinct paths (not raw request count) so that a single
    page hammered repeatedly does not trigger a false positive.
    """

    name = "web_scanner"

    def __init__(self, threshold: int = 10, window_seconds: int = 60) -> None:
        self._threshold = threshold
        self._window = window_seconds
        # ip → deque of (timestamp, path, raw_line)
        self._hits: dict[str, deque] = defaultdict(deque)
        self._alerted: set[str] = set()

    def feed(self, entry: LogEntry) -> Iterator[Incident]:
        if not isinstance(entry, WebEntry) or not entry.source_ip or not entry.timestamp:
            return
        if entry.status_code not in (403, 404):
            return

        ip = entry.source_ip
        if ip in self._alerted:
            return

        buf = self._hits[ip]
        buf.append((entry.timestamp, entry.path, entry.raw))
        self._evict(buf, entry.timestamp, self._window)

        distinct = {e[1] for e in buf}
        if len(distinct) >= self._threshold:
            self._alerted.add(ip)
            yield Incident(
                rule_name=self.name,
                severity=Severity.HIGH,
                source_ip=ip,
                description=(
                    f"Web scanner: {ip} probed {len(distinct)} distinct paths "
                    f"with 403/404 responses within {self._window}s"
                ),
                evidence=[e[2] for e in buf],
                first_seen=buf[0][0],
                last_seen=entry.timestamp,
                count=len(distinct),
            )
