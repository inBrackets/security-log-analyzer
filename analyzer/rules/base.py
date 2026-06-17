from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Iterator
from datetime import datetime

from analyzer.models import Incident, LogEntry


class BaseRule(ABC):
    """
    Stream-oriented detection rule.

    Each rule is a stateful processor that receives log entries one at a time
    and yields Incident objects whenever a pattern is detected.  Adding a new
    detection means subclassing this — existing rules and the engine never
    need to change (Open/Closed Principle).

    Lifecycle
    ---------
    feed(entry)  — called once per log line, in order.  May yield 0-N incidents.
    flush()      — called once after the last entry.  Override to emit incidents
                   that require end-of-stream knowledge (e.g. incomplete patterns).
    """

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def feed(self, entry: LogEntry) -> Iterator[Incident]: ...

    def flush(self) -> Iterator[Incident]:
        return iter([])

    def _evict(self, buf: deque, current: datetime, window: float) -> None:
        while buf and (current - buf[0][0]).total_seconds() > window:
            buf.popleft()
