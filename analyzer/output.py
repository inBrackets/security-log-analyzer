from __future__ import annotations

import json
from datetime import datetime

from analyzer.models import Incident, Severity

_NO_INCIDENTS = "No incidents detected."
_NARRATIVE_WIDTH = 70

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
        return _NO_INCIDENTS

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


def _threat_label(incidents: list[Incident], max_sev: Severity) -> str:
    rules = {i.rule_name for i in incidents}

    if "cross_protocol_brute_force" in rules:
        return "COORDINATED MULTI-VECTOR ATTACK"
    if "suspicious_sudo" in rules:
        return "PRIVILEGE ESCALATION"
    if "sql_injection" in rules and max_sev == Severity.CRITICAL:
        return "POSSIBLE DATA EXFILTRATION"
    if "sql_injection" in rules or "path_traversal" in rules:
        return "EXPLOITATION ATTEMPT"
    if {"ssh_brute_force", "web_brute_force"} & rules:
        return "BREACH" if max_sev == Severity.CRITICAL else "CREDENTIAL ATTACK"
    if "user_enumeration" in rules:
        return "RECONNAISSANCE"
    return "ACTIVE THREAT" if max_sev.value >= Severity.HIGH.value else "SUSPICIOUS ACTIVITY"


def _span_str(inc: Incident) -> str:
    if not inc.first_seen or not inc.last_seen or inc.first_seen == inc.last_seen:
        return ""
    delta = int((inc.last_seen - inc.first_seen).total_seconds())
    return f" over {delta}s"


def format_narrative(incidents: list[Incident]) -> str:
    """
    Groups incidents by attacker IP, orders events chronologically within each
    group, and renders a human-readable attack story sorted by threat severity.
    """
    if not incidents:
        return _NO_INCIDENTS

    by_ip: dict[str, list[Incident]] = {}
    for inc in incidents:
        key = inc.source_ip or "(server-local)"
        by_ip.setdefault(key, []).append(inc)

    for ip_incs in by_ip.values():
        ip_incs.sort(key=lambda i: i.first_seen or datetime.min)

    # Compute max severity per IP once; reuse for both sort order and rendering.
    ip_max: dict[str, Severity] = {
        ip: max(incs, key=lambda i: i.severity.value).severity
        for ip, incs in by_ip.items()
    }
    sorted_ips = sorted(by_ip, key=lambda ip: ip_max[ip].value, reverse=True)

    blocks: list[str] = []

    for ip in sorted_ips:
        ip_incs = by_ip[ip]
        max_sev = ip_max[ip]
        label = _threat_label(ip_incs, max_sev)
        bar = ("=" if max_sev == Severity.CRITICAL else "-") * _NARRATIVE_WIDTH

        lines = [
            bar,
            f"  {ip}  |  {max_sev.name}  |  {label}",
            bar,
        ]

        for inc in ip_incs:
            ts = inc.first_seen.strftime("%H:%M:%S") if inc.first_seen else "??:??:??"
            lines.append(f"\n  {ts}  [{inc.severity.name:<8}]  {inc.rule_name}")
            lines.append(f"    {inc.description}")
            if inc.count > 1:
                span = _span_str(inc)
                lines.append(f"    {inc.count} events{span}")

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


def print_evidence(incidents: list[Incident]) -> None:
    for inc in sorted(incidents, key=lambda i: -i.severity.value):
        print(f"\n{'-' * 72}")
        print(f"[{inc.severity.name}] {inc.rule_name}  --  {inc.source_ip or 'N/A'}")
        print(f"  {inc.description}")
        for line in inc.evidence:
            print(f"    | {line}")
