from __future__ import annotations

from collections.abc import Iterator

from .base import BaseRule
from .ip_tracker import IPTracker
from analyzer.models import AuthEntry, Incident, LogEntry, Severity, WebEntry


class CrossProtocolBruteForceRule(BaseRule):
    """
    Fires when the same IP has brute-force failures across BOTH the SSH layer
    (auth.log) and the HTTP layer (webserver.log) within a shared time window.

    This is a *correlation* rule: it does not perform its own pattern matching
    but reads the aggregated state written by SSHBruteForceRule and
    WebBruteForceRule into the shared IPTracker.

    Why this matters
    ----------------
    A single attacker using the same IP across multiple protocols is a much
    stronger signal than either individual channel alone.  The cross-protocol
    incident should be treated as a coordinated, automated attack (e.g. a
    tool like Hydra running SSH and HTTP modules in parallel).

    When it fires
    -------------
    The check is triggered only when a *new failure event* arrives (either an
    SSH failed-password or an HTTP 401).  This avoids re-evaluating the tracker
    on every log line and keeps the per-entry overhead at a single dict lookup.

    The rule fires at most once per IP per session (_alerted set).
    """

    name = "cross_protocol_brute_force"

    def __init__(
        self,
        tracker: IPTracker,
        threshold_per_protocol: int = 2,
        window_seconds: int = 120,
    ) -> None:
        self._tracker   = tracker
        self._threshold = threshold_per_protocol
        self._window    = window_seconds
        self._alerted: set[str] = set()

    def feed(self, entry: LogEntry) -> Iterator[Incident]:
        if not entry.source_ip or not entry.timestamp:
            return

        # Only re-evaluate when new failure evidence arrives
        if not self._is_failure(entry):
            return

        ip = entry.source_ip
        if ip in self._alerted:
            return

        active = self._tracker.active_failure_protocols(ip, self._window, entry.timestamp)
        if len(active) < 2:
            return  # only one protocol seen so far

        # Both protocols must independently meet the per-protocol threshold
        for proto in active:
            failures = self._tracker.query(
                ip,
                event_type="failure",
                protocol=proto,
                window_seconds=self._window,
                reference_ts=entry.timestamp,
            )
            if len(failures) < self._threshold:
                return  # not enough evidence on this channel yet

        self._alerted.add(ip)

        all_failures = sorted(
            (
                ev
                for proto in active
                for ev in self._tracker.query(
                    ip,
                    event_type="failure",
                    protocol=proto,
                    window_seconds=self._window,
                    reference_ts=entry.timestamp,
                )
            ),
            key=lambda ev: ev.timestamp,
        )

        yield Incident(
            rule_name=self.name,
            severity=Severity.CRITICAL,
            source_ip=ip,
            description=(
                f"Multi-vector brute force: {ip} attacking via "
                f"{' + '.join(p.upper() for p in sorted(active))} simultaneously"
            ),
            evidence=[
                f"[{ev.protocol.upper()}] {ev.detail}" for ev in all_failures
            ],
            first_seen=all_failures[0].timestamp,
            last_seen=entry.timestamp,
            count=len(all_failures),
        )

    @staticmethod
    def _is_failure(entry: LogEntry) -> bool:
        if isinstance(entry, AuthEntry):
            return entry.event_type == "failed_password"
        if isinstance(entry, WebEntry):
            return entry.status_code == 401
        return False
