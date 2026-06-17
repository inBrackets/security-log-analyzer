from __future__ import annotations

import logging
import re
from collections.abc import Generator
from datetime import datetime
from pathlib import Path
from typing import Optional

from .base import BaseParser
from analyzer.models import WebEntry

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Apache / Nginx Combined Log Format (CLF)
#
#   192.168.1.10 - - [03/Jul/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
#
# The request-path field uses a non-greedy match (.*?) so that URLs containing
# literal spaces (e.g. SQL injection payloads like "/search?q=' UNION SELECT …")
# are captured in full rather than truncated at the first space.
# ---------------------------------------------------------------------------
_CLF_RE = re.compile(
    r'(?P<ip>\S+)'           # client IP
    r' \S+'                  # ident (always "-")
    r' \S+'                  # auth user (usually "-")
    r' \[(?P<ts>[^\]]+)\]'  # [timestamp tz]
    r' "(?P<method>\S+)'     # "METHOD
    r' (?P<path>.*?)'        # /path?query  (non-greedy, stops before " HTTP/")
    r' HTTP/(?P<ver>[\d.]+)"' # HTTP/1.1"
    r' (?P<status>\d{3})'   # status code
    r' (?P<size>\d+)'        # response bytes
)
_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


class WebLogParser(BaseParser):
    """
    Parses Apache/Nginx Combined Log Format (CLF) files into WebEntry objects.

    Error handling
    --------------
    - Lines that do not match the CLF regex (e.g. "[MALFORMED ENTRY …") are
      logged at WARNING level with the file name and 1-based line number, then
      skipped; the generator continues yielding from subsequent lines.
    - Unexpected exceptions inside _parse_line() are caught, logged at ERROR
      level with a full traceback, and the line is skipped.
    - Encoding errors (binary data in log) are replaced by U+FFFD on read so
      a single corrupted byte never raises UnicodeDecodeError for the whole file.
    - Blank lines are silently ignored.
    """

    def parse(self, path: Path) -> Generator[WebEntry, None, None]:
        _log.debug("Opening %s", path)
        with open(path, encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                raw = raw.rstrip("\n")

                if not raw.strip():
                    continue  # blank lines — silent

                try:
                    entry = self._parse_line(raw)
                except Exception:
                    # Defensive catch: e.g. int() on a 3-digit status that
                    # somehow slips through, or an unforeseen regex edge-case.
                    _log.error(
                        "[%s:%d] Unexpected error — skipping line: %.120r",
                        path.name, lineno, raw,
                        exc_info=True,
                    )
                    continue

                if entry is None:
                    # Non-blank line that doesn't match CLF — log and move on.
                    _log.warning(
                        "[%s:%d] Unrecognised format — skipping: %.120r",
                        path.name, lineno, raw,
                    )
                    continue

                yield entry

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_line(self, raw: str) -> Optional[WebEntry]:
        m = _CLF_RE.match(raw)
        if not m:
            return None  # caller logs the warning

        try:
            # Strip timezone so timestamps are naive and comparable with
            # auth.log entries (which carry no tz info).
            ts = datetime.strptime(m.group("ts"), _TS_FMT).replace(tzinfo=None)
        except ValueError:
            _log.debug("Cannot parse CLF timestamp %r", m.group("ts"))
            ts = None

        full_path = m.group("path")
        path, _, query = full_path.partition("?")

        return WebEntry(
            raw=raw,
            timestamp=ts,
            source_ip=m.group("ip"),
            method=m.group("method"),
            path=path,
            query=query,
            http_version=m.group("ver"),
            status_code=int(m.group("status")),
            response_size=int(m.group("size")),
        )
