from __future__ import annotations

import logging
import re
from collections.abc import Generator
from datetime import datetime
from pathlib import Path
from typing import Optional

from .base import BaseParser
from analyzer.models import AuthEntry

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Syslog header
#   "Jul  3 10:00:03 server sshd[1234]: message"
#   Month is 3 chars, day is 1-2 digits (may be space-padded on some systems).
# ---------------------------------------------------------------------------
_HEADER = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:]+):\s+(?P<msg>.+)$"
)
_PROC_PID = re.compile(r"^(?P<name>\w+)\[(?P<pid>\d+)\]$")

# ---------------------------------------------------------------------------
# sshd message patterns
# ---------------------------------------------------------------------------
_SSHD_FAILED = re.compile(
    r"Failed password for (?P<inv>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) (?P<proto>\S+)"
)
_SSHD_ACCEPTED = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) (?P<proto>\S+)"
)
_SSHD_CLOSED = re.compile(
    r"Connection closed by (?:authenticating user \S+ )?(?P<ip>\S+) port (?P<port>\d+)"
)

# ---------------------------------------------------------------------------
# sudo message pattern
#   "johndoe : TTY=pts/0 ; PWD=/home/johndoe ; USER=root ; COMMAND=/bin/cat /etc/shadow"
# ---------------------------------------------------------------------------
_SUDO = re.compile(
    r"(?P<user>\S+)\s+:\s+TTY=\S+\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+"
    r"USER=(?P<target>\S+)\s+;\s+COMMAND=(?P<cmd>.+)"
)


class AuthLogParser(BaseParser):
    """
    Parses syslog-format auth.log files into a stream of AuthEntry objects.

    Error handling
    --------------
    - Lines that do not match the syslog header regex are logged at WARNING
      level and skipped; the stream continues.
    - Any unexpected exception inside _parse_line() is logged at ERROR level
      (with full traceback) and the line is skipped.
    - Binary garbage is replaced by U+FFFD on read (errors="replace"), so a
      corrupted byte sequence never raises UnicodeDecodeError.
    - Blank lines are silently ignored.
    """

    def __init__(self, year: int | None = None) -> None:
        self._year = year if year is not None else datetime.now().year

    def parse(self, path: Path) -> Generator[AuthEntry, None, None]:
        _log.debug("Opening %s", path)
        with open(path, encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                raw = raw.rstrip("\n")

                if not raw.strip():
                    continue  # blank lines — silent

                try:
                    entry = self._parse_line(raw)
                except Exception:
                    # Unexpected error (e.g. int() on malformed port number).
                    # Log full traceback so it can be investigated, then keep going.
                    _log.error(
                        "[%s:%d] Unexpected error — skipping line: %.120r",
                        path.name, lineno, raw,
                        exc_info=True,
                    )
                    continue

                if entry is None:
                    # Line is non-blank but did not match any known pattern.
                    _log.warning(
                        "[%s:%d] Unrecognised format — skipping: %.120r",
                        path.name, lineno, raw,
                    )
                    continue

                yield entry

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_line(self, raw: str) -> Optional[AuthEntry]:
        m = _HEADER.match(raw)
        if not m:
            return None  # caller logs the warning

        ts = self._parse_timestamp(m.group("ts"))

        proc_str = m.group("proc").strip()
        pm = _PROC_PID.match(proc_str)
        process = pm.group("name") if pm else proc_str
        pid     = int(pm.group("pid")) if pm else None

        entry = AuthEntry(
            raw=raw,
            timestamp=ts,
            source_ip=None,
            hostname=m.group("host"),
            process=process,
            pid=pid,
        )

        msg = m.group("msg")
        if process == "sshd":
            self._parse_sshd(entry, msg)
        elif process == "sudo":
            self._parse_sudo(entry, msg)

        return entry

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        # Normalise "Jul  3" (double space for single-digit day) → "Jul 3"
        normalised = " ".join(ts_str.split())
        try:
            return datetime.strptime(f"{self._year} {normalised}", "%Y %b %d %H:%M:%S")
        except ValueError:
            _log.debug("Cannot parse timestamp %r", ts_str)
            return None

    def _parse_sshd(self, entry: AuthEntry, msg: str) -> None:
        if m := _SSHD_FAILED.search(msg):
            entry.event_type     = "failed_password"
            entry.username       = m.group("user")
            entry.source_ip      = m.group("ip")
            entry.port           = int(m.group("port"))
            entry.protocol       = m.group("proto")
            entry.is_invalid_user = bool(m.group("inv"))
            return

        if m := _SSHD_ACCEPTED.search(msg):
            entry.event_type = "accepted_password"
            entry.username   = m.group("user")
            entry.source_ip  = m.group("ip")
            entry.port       = int(m.group("port"))
            entry.protocol   = m.group("proto")
            return

        if m := _SSHD_CLOSED.search(msg):
            entry.event_type = "connection_closed"
            entry.source_ip  = m.group("ip")
            entry.port       = int(m.group("port"))

    def _parse_sudo(self, entry: AuthEntry, msg: str) -> None:
        if m := _SUDO.search(msg):
            entry.event_type  = "sudo"
            entry.username    = m.group("user")
            entry.target_user = m.group("target")
            entry.sudo_cwd    = m.group("pwd")
            entry.sudo_command = m.group("cmd").strip()
