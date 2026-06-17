from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import unquote_plus

from .base import BaseRule
from analyzer.models import Incident, LogEntry, Severity, WebEntry

_TRAVERSAL = re.compile(r"\.\.[/\\]|%2e%2e[%2f%5c]", re.IGNORECASE)
_SENSITIVE = re.compile(r"etc/(?:passwd|shadow)|win\.ini|boot\.ini|\.ssh/", re.IGNORECASE)


class PathTraversalRule(BaseRule):
    """
    Detects directory traversal sequences in the request path.
    Escalates to CRITICAL when the traversal targets known-sensitive files.
    """

    name = "path_traversal"

    def feed(self, entry: LogEntry) -> Iterator[Incident]:
        if not isinstance(entry, WebEntry):
            return

        target = entry.path + ("?" + entry.query if entry.query else "")
        decoded = unquote_plus(target)

        if not _TRAVERSAL.search(decoded) and "../" not in decoded:
            return

        severity = Severity.CRITICAL if _SENSITIVE.search(decoded) else Severity.HIGH

        yield Incident(
            rule_name=self.name,
            severity=severity,
            source_ip=entry.source_ip,
            description=f"Path traversal attempt: '{entry.path}'",
            evidence=[entry.raw, f"Decoded target: {decoded}"],
            first_seen=entry.timestamp,
            last_seen=entry.timestamp,
        )
