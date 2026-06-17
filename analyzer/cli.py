from __future__ import annotations

import argparse
import logging
import sys
from itertools import chain
from pathlib import Path

from analyzer.engine import AnalysisEngine
from analyzer.models import Severity
from analyzer.parsers.auth_parser import AuthLogParser
from analyzer.parsers.web_parser import WebLogParser
from analyzer.rules import build_rules
from analyzer import output


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Security log analyzer — streaming detection for auth and web logs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--log-dir", type=Path, default=Path("logs"),
        help="Directory containing auth.log and webserver.log",
    )
    p.add_argument("--auth-log", type=Path, help="Explicit path to auth.log (overrides --log-dir)")
    p.add_argument("--web-log",  type=Path, help="Explicit path to webserver.log (overrides --log-dir)")
    p.add_argument(
        "--output", choices=["table", "json"], default="table",
        help="Output format",
    )
    p.add_argument(
        "--min-severity",
        choices=[s.name for s in Severity],
        default="MEDIUM",
        help="Minimum severity level to report",
    )
    p.add_argument(
        "--show-evidence", action="store_true",
        help="Print supporting log lines beneath each incident",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show parse warnings and debug info on stderr",
    )
    p.add_argument(
        "--parse-log", type=Path, metavar="FILE",
        help="Write parse warnings/errors to FILE instead of (or in addition to) stderr",
    )
    return p


def _configure_logging(verbose: bool, parse_log: Path | None) -> None:
    """
    Route parse warnings to stderr and optionally to a dedicated file.

    Without --verbose  → only WARNING and above reach stderr.
    With    --verbose  → DEBUG messages are also shown (useful when investigating
                         why a specific line was skipped).
    With    --parse-log → warnings/errors are written to that file as well,
                          which is useful in automated pipelines where stderr
                          output is discarded.
    """
    root = logging.getLogger("analyzer.parsers")
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)

    fmt = logging.Formatter("%(levelname)-8s %(name)s: %(message)s")

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    stderr_handler.setFormatter(fmt)
    root.addHandler(stderr_handler)

    if parse_log:
        file_handler = logging.FileHandler(parse_log, encoding="utf-8")
        file_handler.setLevel(logging.WARNING)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        )
        root.addHandler(file_handler)


def run(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _configure_logging(args.verbose, args.parse_log)

    auth_path = args.auth_log or args.log_dir / "auth.log"
    web_path  = args.web_log  or args.log_dir / "webserver.log"

    missing = [str(p) for p in (auth_path, web_path) if not p.exists()]
    if missing:
        print(f"ERROR: file(s) not found: {', '.join(missing)}", file=sys.stderr)
        return 1

    rules = build_rules()
    engine = AnalysisEngine(rules)

    # Stream both parsers as a single lazy sequence — neither file is loaded whole
    entries = chain(
        AuthLogParser().parse(auth_path),
        WebLogParser().parse(web_path),
    )

    min_sev = Severity[args.min_severity]
    incidents = [
        inc for inc in engine.analyze(entries)
        if inc.severity.value >= min_sev.value
    ]

    if args.output == "json":
        print(output.format_json(incidents))
    else:
        print(output.format_table(incidents))
        if args.show_evidence:
            output.print_evidence(incidents)

    return 0
