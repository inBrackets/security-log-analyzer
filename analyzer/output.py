from __future__ import annotations

import json

from analyzer.models import Incident, Severity

_COLS: list[tuple[str, int]] = [
    ("SEVERITY",    9),
    ("RULE",        22),
    ("SOURCE IP",   17),
    ("DESCRIPTION", 55),
    ("#",            4),
    ("FIRST SEEN",  19),
]
_SEP = " | "
_DIV = "-+-".join("-" * w for _, w in _COLS)


def format_table(incidents: list[Incident]) -> str:
    if not incidents:
        return "No incidents detected."

    header = _SEP.join(f"{h:<{w}}" for h, w in _COLS)
    rows = [header, _DIV]

    for inc in sorted(incidents, key=lambda i: (-i.severity.value, i.first_seen or "")):
        ts = inc.first_seen.strftime("%Y-%m-%d %H:%M:%S") if inc.first_seen else "N/A"
        desc = inc.description
        max_w = _COLS[3][1] - 2
        if len(desc) > max_w:
            desc = desc[:max_w] + "..."

        values = [
            (inc.severity.name,    _COLS[0][1]),
            (inc.rule_name,        _COLS[1][1]),
            (inc.source_ip or "N/A", _COLS[2][1]),
            (desc,                 _COLS[3][1]),
            (str(inc.count),       _COLS[4][1]),
            (ts,                   _COLS[5][1]),
        ]
        rows.append(_SEP.join(f"{v:<{w}}" for v, w in values))

    return "\n".join(rows)


def format_json(incidents: list[Incident]) -> str:
    def _ser(inc: Incident) -> dict:
        return {
            "rule": inc.rule_name,
            "severity": inc.severity.name,
            "source_ip": inc.source_ip,
            "description": inc.description,
            "count": inc.count,
            "first_seen": inc.first_seen.isoformat() if inc.first_seen else None,
            "last_seen": inc.last_seen.isoformat() if inc.last_seen else None,
            "evidence": inc.evidence,
        }
    return json.dumps([_ser(i) for i in incidents], indent=2)


def print_evidence(incidents: list[Incident]) -> None:
    for inc in sorted(incidents, key=lambda i: -i.severity.value):
        print(f"\n{'-' * 72}")
        print(f"[{inc.severity.name}] {inc.rule_name}  --  {inc.source_ip or 'N/A'}")
        print(f"  {inc.description}")
        for line in inc.evidence:
            print(f"    | {line}")
