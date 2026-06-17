"""
Tests for AuthLogParser — syslog format parsing, error recovery, and timestamp edge cases.
"""
from __future__ import annotations

import logging
from datetime import datetime

import pytest

from analyzer.parsers.auth_parser import AuthLogParser


# ---------------------------------------------------------------------------
# Parametrised happy-path cases: (raw_line, expected_field_dict)
# ---------------------------------------------------------------------------

VALID_SYSLOG_LINES = [
    pytest.param(
        "Jul  3 10:00:03 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52341 ssh2",
        {
            "event_type": "failed_password",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "port": 52341,
            "protocol": "ssh2",
            "is_invalid_user": False,
        },
        id="failed_password_valid_user",
    ),
    pytest.param(
        "Jul  3 10:00:09 server sshd[1235]: Failed password for invalid user guest from 203.0.113.5 port 44123 ssh2",
        {
            "event_type": "failed_password",
            "username": "guest",
            "source_ip": "203.0.113.5",
            "port": 44123,
            "is_invalid_user": True,
        },
        id="failed_password_invalid_user",
    ),
    pytest.param(
        "Jul  3 10:00:07 server sshd[1234]: Accepted password for admin from 10.0.0.50 port 52345 ssh2",
        {
            "event_type": "accepted_password",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "port": 52345,
        },
        id="accepted_password",
    ),
    pytest.param(
        "Jul  3 10:00:18 server sshd[1240]: Accepted publickey for deploy from 192.168.1.100 port 39281 ssh2",
        {
            "event_type": "accepted_password",
            "username": "deploy",
            "source_ip": "192.168.1.100",
            "port": 39281,
        },
        id="accepted_publickey",
    ),
    pytest.param(
        "Jul  3 10:00:15 server sudo: johndoe : TTY=pts/0 ; PWD=/home/johndoe ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        {
            "event_type": "sudo",
            "username": "johndoe",
            "target_user": "root",
            "sudo_command": "/bin/cat /etc/shadow",
            "sudo_cwd": "/home/johndoe",
        },
        id="sudo_command",
    ),
    pytest.param(
        "Jul  3 10:00:25 server sshd[1245]: Connection closed by 10.0.0.50 port 52345 [preauth]",
        {
            "event_type": "connection_closed",
            "source_ip": "10.0.0.50",
            "port": 52345,
        },
        id="connection_closed",
    ),
    pytest.param(
        "Jul 15 08:12:44 webserver sshd[999]: Failed password for root from 198.51.100.7 port 1022 ssh2",
        {
            "event_type": "failed_password",
            "username": "root",
            "source_ip": "198.51.100.7",
            "port": 1022,
        },
        id="double_digit_day",
    ),
]


@pytest.mark.parametrize("line,expected", VALID_SYSLOG_LINES)
def test_valid_line_parses_correctly(tmp_path, line, expected):
    log_file = tmp_path / "auth.log"
    log_file.write_text(line + "\n", encoding="utf-8")

    entries = list(AuthLogParser().parse(log_file))

    assert len(entries) == 1, f"Expected 1 entry, got {len(entries)}"
    entry = entries[0]
    for field, value in expected.items():
        actual = getattr(entry, field)
        assert actual == value, f"Field {field!r}: expected {value!r}, got {actual!r}"


# ---------------------------------------------------------------------------
# Timestamp edge cases
# ---------------------------------------------------------------------------

def test_single_digit_day_with_double_space_is_parsed(tmp_path):
    """syslog uses a leading space for single-digit days: 'Jul  3' not 'Jul 3'."""
    line = "Jul  3 09:30:00 server sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    log_file = tmp_path / "auth.log"
    log_file.write_text(line + "\n", encoding="utf-8")

    entries = list(AuthLogParser(year=2025).parse(log_file))

    assert len(entries) == 1
    assert entries[0].timestamp == datetime(2025, 7, 3, 9, 30, 0)


def test_year_injected_from_constructor(tmp_path):
    """Custom year is applied to every parsed timestamp."""
    line = "Mar 15 12:00:00 server sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    log_file = tmp_path / "auth.log"
    log_file.write_text(line + "\n", encoding="utf-8")

    entries = list(AuthLogParser(year=2024).parse(log_file))

    assert entries[0].timestamp == datetime(2024, 3, 15, 12, 0, 0)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_blank_lines_silently_skipped(tmp_path):
    valid = "Jul  3 10:00:03 server sshd[1]: Failed password for a from 1.1.1.1 port 22 ssh2"
    log_file = tmp_path / "auth.log"
    log_file.write_text(f"\n{valid}\n\n\n", encoding="utf-8")

    entries = list(AuthLogParser().parse(log_file))

    assert len(entries) == 1


def test_malformed_line_logs_warning_and_is_skipped(tmp_path, caplog):
    valid = "Jul  3 10:00:03 server sshd[1]: Failed password for a from 1.1.1.1 port 22 ssh2"
    log_file = tmp_path / "auth.log"
    log_file.write_text(f"{valid}\n[MALFORMED ENTRY - system restart\n{valid}\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="analyzer.parsers.auth_parser"):
        entries = list(AuthLogParser().parse(log_file))

    assert len(entries) == 2, "Malformed line should be skipped; valid lines should be yielded"

    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("Unrecognised format" in m for m in warning_msgs), "Expected an 'Unrecognised format' warning"
    assert any("auth.log:2" in m for m in warning_msgs), "Warning should reference line 2"


def test_malformed_line_does_not_stop_subsequent_parsing(tmp_path):
    lines = [
        "Jul  3 10:00:01 server sshd[1]: Failed password for alpha from 1.1.1.1 port 22 ssh2",
        "[MALFORMED ENTRY - system restart",
        "Jul  3 10:00:02 server sshd[2]: Failed password for beta from 2.2.2.2 port 23 ssh2",
        "Jul  3 10:00:03 server sshd[3]: Failed password for gamma from 3.3.3.3 port 24 ssh2",
    ]
    log_file = tmp_path / "auth.log"
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    entries = list(AuthLogParser().parse(log_file))

    assert len(entries) == 3
    assert entries[0].username == "alpha"
    assert entries[1].username == "beta"
    assert entries[2].username == "gamma"


def test_multiple_malformed_lines_are_each_logged(tmp_path, caplog):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "[NOT SYSLOG 1]\n"
        "[NOT SYSLOG 2]\n"
        "Jul  3 10:00:01 server sshd[1]: Failed password for a from 1.1.1.1 port 22 ssh2\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="analyzer.parsers.auth_parser"):
        entries = list(AuthLogParser().parse(log_file))

    assert len(entries) == 1
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 2
