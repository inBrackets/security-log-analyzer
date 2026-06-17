from __future__ import annotations

from collections.abc import Iterator

from .base import BaseRule
from analyzer.models import AuthEntry, Incident, LogEntry, Severity

_SENSITIVE_TARGETS = [
    "/etc/shadow",
    "/etc/passwd",
    "id_rsa",
    ".ssh/",
    "sudoers",
    "/proc/",
    "/dev/mem",
]


class SuspiciousSudoRule(BaseRule):
    """
    Flags sudo commands that access credential or key material files.
    These are high-value post-compromise targets.
    """

    name = "suspicious_sudo"

    def feed(self, entry: LogEntry) -> Iterator[Incident]:
        if not isinstance(entry, AuthEntry) or entry.event_type != "sudo":
            return
        if not entry.sudo_command:
            return

        matched = [t for t in _SENSITIVE_TARGETS if t in entry.sudo_command]
        if not matched:
            return

        yield Incident(
            rule_name=self.name,
            severity=Severity.CRITICAL,
            source_ip=None,
            description=(
                f"Suspicious sudo: '{entry.username}' ran "
                f"'{entry.sudo_command}' as '{entry.target_user}'"
            ),
            evidence=[entry.raw, f"Sensitive targets: {matched}"],
            first_seen=entry.timestamp,
            last_seen=entry.timestamp,
        )
