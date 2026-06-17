from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import unquote_plus

from .base import BaseRule
from analyzer.models import Incident, LogEntry, Severity, WebEntry


@dataclass(frozen=True)
class _Signal:
    name: str
    pattern: re.Pattern[str]
    score: int


# ---------------------------------------------------------------------------
# Signal bank — each entry targets unambiguous SQL *structure*, not content.
#
# Scoring rationale (why this avoids the O'Brien false-positive):
#
#   score 10 — unambiguous multi-word SQL command; no innocent meaning
#   score  8 — structural keyword that appears inside SQL logic
#   score  7 — string-terminator immediately followed by SQL comment
#               ("admin'--" is a classic injection; "O'Brien" is not because
#               there is no "--" after the apostrophe)
#   score  6 — boolean tautology pattern requires "OR" + two equal numbers
#   score  5 — apostrophe followed by a SQL comparison operator
#   score  4 — standalone SQL comment marker (raises suspicion in context)
#
# Threshold = 6:
#   "O'Brien"               →  0 pts  (no pattern fires)          → NO alert ✓
#   "O'Brien AND 1=1"       →  6 pts  (OR tautology)              → alerts  ✓
#   "admin'--"              → 11 pts  (str+comment 7 + comment 4) → alerts  ✓
#   "' OR 1=1--"            → 17 pts  (tautol 6+str+cmt 7+cmt 4) → alerts  ✓
#   "' UNION SELECT…--"     → 21 pts  (UNION 10+str+cmt 7+cmt 4) → alerts  ✓
#   "1; DROP TABLE users--" → 22 pts  (DROP 10+stack 8+cmt 4)    → alerts  ✓
# ---------------------------------------------------------------------------
_SIGNALS: list[_Signal] = [
    _Signal(
        "UNION SELECT",
        re.compile(r"(?i)\bunion\s+select\b"),
        10,
    ),
    _Signal(
        "DROP TABLE",
        re.compile(r"(?i)\bdrop\s+table\b"),
        10,
    ),
    _Signal(
        "EXEC/EXECUTE",
        re.compile(r"(?i)\bexec(?:ute)?\s*\("),
        8,
    ),
    _Signal(
        "INFORMATION_SCHEMA",
        re.compile(r"(?i)\binformation_schema\b"),
        8,
    ),
    _Signal(
        "stacked query",
        # semicolon then a DML/DDL keyword — "1; DROP TABLE …"
        re.compile(r";\s*\b(?:select|insert|update|delete|drop|create|alter)\b", re.IGNORECASE),
        8,
    ),
    _Signal(
        "string terminator + comment",
        # apostrophe directly followed by SQL line comment — "admin'--"
        re.compile(r"'\s*--"),
        7,
    ),
    _Signal(
        "boolean tautology",
        # requires OR + two numeric expressions — "OR 1=1", "OR 2>1"
        re.compile(r"(?i)\bor\b\s+\d+\s*[=<>]\s*\d+"),
        6,
    ),
    _Signal(
        "quote + comparison operator",
        # apostrophe followed by =, !=, <>, AND, OR — "' OR '1"
        re.compile(r"'\s*(?:=|!=|<>|and\b|or\b)", re.IGNORECASE),
        5,
    ),
    _Signal(
        "SQL line comment (--)",
        # standalone comment marker; low weight because "-- " appears in
        # some markdown-like content, but combined with other signals it matters
        re.compile(r"--\s*(?:'|\"|#|\s*$)"),
        4,
    ),
    _Signal(
        "SQL block comment (/**/)",
        re.compile(r"/\*.*?\*/"),
        4,
    ),
]

_THRESHOLD = 6


class SQLInjectionRule(BaseRule):
    """
    Detects SQL injection payloads in decoded URL query strings using a
    weighted signal model instead of a simple keyword match.

    A single apostrophe — as in a name like O'Brien — scores 0 and produces
    no alert.  Only combinations of structural SQL markers (keyword pairs,
    comment sequences, tautology patterns) accumulate enough score to fire.

    Severity
    --------
    CRITICAL  when the server responded HTTP 200 (the payload may have
              reached the database and returned data).
    HIGH      when the server responded with an error (4xx/5xx) — the
              attempt was likely blocked but the intent is clear.
    """

    name = "sql_injection"

    def __init__(self, threshold: int = _THRESHOLD) -> None:
        self._threshold = threshold

    def feed(self, entry: LogEntry) -> Iterator[Incident]:
        if not isinstance(entry, WebEntry) or not entry.query:
            return

        # Decode percent-encoding so "UNION%20SELECT" is caught as "UNION SELECT"
        decoded = unquote_plus(entry.query)

        fired: list[_Signal] = [s for s in _SIGNALS if s.pattern.search(decoded)]
        total_score = sum(s.score for s in fired)

        if total_score < self._threshold:
            return

        severity = Severity.CRITICAL if entry.status_code == 200 else Severity.HIGH
        note = (
            " - server returned 200, payload may have reached the DB"
            if entry.status_code == 200 else ""
        )

        yield Incident(
            rule_name=self.name,
            severity=severity,
            source_ip=entry.source_ip,
            description=f"SQL injection on '{entry.path}'{note}",
            evidence=[
                entry.raw,
                f"Score: {total_score}/{self._threshold} — signals: {[s.name for s in fired]}",
                f"Decoded query: {decoded[:300]}",
            ],
            first_seen=entry.timestamp,
            last_seen=entry.timestamp,
        )
