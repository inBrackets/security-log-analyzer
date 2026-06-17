from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class IPEvent:
    timestamp: datetime
    protocol: str    # "ssh" | "web"
    event_type: str  # "failure" | "success"
    detail: str      # human-readable context (username, path, …)


class IPTracker:
    """
    Time-bounded, per-IP event accumulator shared across rule instances.

    Memory model
    ------------
    Events are stored in a per-IP deque.  Eviction is lazy: stale entries are
    removed the next time a *new* event arrives for the same IP.  No background
    thread or timer is needed.  Memory is bounded to:

        O(unique_active_IPs  ×  avg_events_within_TTL)

    For a server with 10 000 unique attacking IPs and a 5-minute TTL at
    ~100 req/s per IP worst-case, each IPEvent costs ≈ 200 bytes → well
    under 100 MB in practice.

    Thread safety
    -------------
    Not thread-safe by design: the streaming engine is single-threaded.
    If you ever parallelize parsing, wrap `record` / `query` with a Lock.

    Usage
    -----
    One instance is constructed in `build_rules()` and injected via constructor
    into every rule that needs cross-rule correlation.  Rules write events as
    they detect them; correlation rules read the aggregated state.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl = ttl_seconds
        self._store: dict[str, deque[IPEvent]] = defaultdict(deque)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(self, ip: str, event: IPEvent) -> None:
        buf = self._store[ip]
        buf.append(event)
        self._evict(buf, event.timestamp)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def query(
        self,
        ip: str,
        *,
        event_type: str | None = None,
        protocol: str | None = None,
        window_seconds: int | None = None,
        reference_ts: datetime | None = None,
    ) -> list[IPEvent]:
        """
        Return stored events for *ip*, optionally filtered by event type,
        protocol, and/or time window relative to *reference_ts*.
        """
        window = window_seconds if window_seconds is not None else self._ttl
        ref    = reference_ts or datetime.now()

        return [
            ev for ev in self._store.get(ip, [])
            if (event_type is None or ev.event_type == event_type)
            and (protocol   is None or ev.protocol   == protocol)
            and (ref - ev.timestamp).total_seconds() <= window
        ]

    def active_failure_protocols(
        self,
        ip: str,
        window_seconds: int,
        reference_ts: datetime,
    ) -> set[str]:
        """Return the set of protocols that have at least one failure in the window."""
        return {
            ev.protocol
            for ev in self.query(
                ip,
                event_type="failure",
                window_seconds=window_seconds,
                reference_ts=reference_ts,
            )
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _evict(self, buf: deque[IPEvent], current: datetime) -> None:
        while buf and (current - buf[0].timestamp).total_seconds() > self._ttl:
            buf.popleft()
