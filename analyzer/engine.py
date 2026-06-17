from __future__ import annotations

from collections.abc import Generator, Iterable

from analyzer.models import Incident, LogEntry
from analyzer.rules.base import BaseRule


class AnalysisEngine:
    """
    Streaming pipeline: feeds each LogEntry to every rule in sequence,
    yielding Incidents as they are detected.  The engine never buffers
    entries — memory usage is bounded by the rules' own sliding windows.
    """

    def __init__(self, rules: list[BaseRule]) -> None:
        self._rules = rules

    def analyze(self, entries: Iterable[LogEntry]) -> Generator[Incident, None, None]:
        for entry in entries:
            for rule in self._rules:
                yield from rule.feed(entry)
        # Let stateful rules emit anything they held until end-of-stream
        for rule in self._rules:
            yield from rule.flush()
