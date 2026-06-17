from __future__ import annotations

import argparse
import logging
import sys
from datetime import date, datetime
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
        "--output", choices=["table", "json", "narrative"], default="table",
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
        "--start", metavar="DATETIME",
        help="Show only incidents at or after this time (YYYY-MM-DD HH:MM or YYYY-MM-DD)",
    )
    p.add_argument(
        "--end", metavar="DATETIME",
        help="Show only incidents at or before this time (YYYY-MM-DD HH:MM or YYYY-MM-DD)",
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
    root.handlers.clear()  # prevent duplicate handlers when called in a loop
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


def _choose(prompt: str, options: list[tuple[str, str]], default_idx: int = 0) -> str:
    print(f"\n{prompt}")
    for i, (label, desc) in enumerate(options):
        tag = " (default)" if i == default_idx else ""
        suffix = f"  {desc}" if desc else ""
        print(f"  {i + 1}) {label}{suffix}{tag}")
    while True:
        raw = input("  > ").strip()
        if not raw:
            return options[default_idx][0]
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        print(f"  Enter a number between 1 and {len(options)}.")


def _ask_yes_no(prompt: str, default: bool = False) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    raw = input(f"\n  {prompt} {hint}: ").strip().lower()
    return default if not raw else raw.startswith("y")


def _parse_dt(s: str) -> datetime | None:
    s = s.strip()
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        raise ValueError(f"Cannot parse {s!r} -- use YYYY-MM-DD HH:MM or YYYY-MM-DD")


def _ask_datetime_opt(label: str, example: str) -> str:
    while True:
        raw = input(f"  {label} [e.g. {example}, blank = no limit]: ").strip()
        if not raw:
            return ""
        try:
            _parse_dt(raw)
            return raw
        except ValueError as e:
            print(f"  {e}")


def _interactive_menu() -> list[str]:
    print("\nSecurity Log Analyzer")
    print("=" * 30)

    print("\nLog directory (must contain auth.log and webserver.log):")
    log_dir = input("  Path [logs]: ").strip() or "logs"

    fmt = _choose(
        "Output format:",
        [
            ("narrative", "attack story grouped by IP"),
            ("table",     "flat columnar summary"),
            ("json",      "machine-readable JSON"),
        ],
        default_idx=0,
    )

    sev = _choose(
        "Minimum severity to report:",
        [
            ("MEDIUM",   "brute force, injection, traversal, escalation"),
            ("HIGH",     "confirmed multi-attempt attacks"),
            ("CRITICAL", "breaches and confirmed compromises only"),
            ("LOW",      ""),
            ("INFO",     "everything"),
        ],
        default_idx=0,
    )

    today = date.today().isoformat()
    print("\nTime range filter:")
    start_str = _ask_datetime_opt("From", f"{today} 00:00")
    end_str   = _ask_datetime_opt("To  ", f"{today} 23:59")

    argv = ["--log-dir", log_dir, "--output", fmt, "--min-severity", sev]
    if start_str:
        argv += ["--start", start_str]
    if end_str:
        argv += ["--end", end_str]

    if fmt == "table" and _ask_yes_no("Show supporting log lines?", default=False):
        argv.append("--show-evidence")

    print("\n" + "-" * 30 + "\n")
    return argv


def _execute(argv: list[str]) -> int:
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

    entries = chain(
        AuthLogParser().parse(auth_path),
        WebLogParser().parse(web_path),
    )

    min_sev = Severity[args.min_severity]
    incidents = [
        inc for inc in engine.analyze(entries)
        if inc.severity.value >= min_sev.value
    ]

    try:
        start_dt = _parse_dt(args.start) if args.start else None
        end_dt   = _parse_dt(args.end)   if args.end   else None
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if start_dt or end_dt:
        incidents = [
            inc for inc in incidents
            if inc.first_seen
            and (start_dt is None or inc.first_seen >= start_dt)
            and (end_dt   is None or inc.first_seen <= end_dt)
        ]

    if args.output == "json":
        print(output.format_json(incidents))
    elif args.output == "narrative":
        print(output.format_narrative(incidents))
    else:
        print(output.format_table(incidents))
        if args.show_evidence:
            output.print_evidence(incidents)

    return 0


def run(argv: list[str] | None = None) -> int:
    if argv is None and not sys.argv[1:]:
        while True:
            chosen = _interactive_menu()
            _execute(chosen)
            ans = input("\nPress Enter to return to main menu, or Q to quit: ").strip().lower()
            if ans.startswith("q"):
                print()
                break
        return 0

    return _execute(argv)


if __name__ == "__main__":
    sys.exit(run())
