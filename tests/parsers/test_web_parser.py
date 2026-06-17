"""
Tests for WebLogParser — CLF format parsing, malformed-entry recovery, and URL edge cases.
"""
from __future__ import annotations

import logging
from datetime import datetime

import pytest

from analyzer.parsers.web_parser import WebLogParser


# ---------------------------------------------------------------------------
# Parametrised happy-path cases
# ---------------------------------------------------------------------------

VALID_CLF_LINES = [
    pytest.param(
        '192.168.1.1 - - [03/Jul/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234',
        {
            "method": "GET",
            "path": "/index.html",
            "query": "",
            "status_code": 200,
            "source_ip": "192.168.1.1",
            "response_size": 1234,
            "http_version": "1.1",
        },
        id="simple_get",
    ),
    pytest.param(
        '10.0.0.50 - - [03/Jul/2025:10:00:04 +0000] "POST /login HTTP/1.1" 401 532',
        {
            "method": "POST",
            "path": "/login",
            "query": "",
            "status_code": 401,
            "source_ip": "10.0.0.50",
        },
        id="post_login_401",
    ),
    pytest.param(
        '10.0.0.50 - - [03/Jul/2025:10:00:07 +0000] "POST /login HTTP/1.1" 200 2100',
        {
            "method": "POST",
            "path": "/login",
            "status_code": 200,
        },
        id="post_login_200",
    ),
    pytest.param(
        '192.168.1.10 - - [03/Jul/2025:10:00:05 +0000] "GET /search?q=hello HTTP/1.1" 200 980',
        {
            "method": "GET",
            "path": "/search",
            "query": "q=hello",
            "status_code": 200,
        },
        id="get_with_query_string",
    ),
    pytest.param(
        '203.0.113.5 - - [03/Jul/2025:10:00:10 +0000] "GET /wp-login.php HTTP/1.1" 404 512',
        {
            "path": "/wp-login.php",
            "status_code": 404,
            "source_ip": "203.0.113.5",
        },
        id="wp_login_404",
    ),
    pytest.param(
        # URL with literal spaces — SQL injection payload; non-greedy path regex catches it
        "10.0.0.50 - - [03/Jul/2025:10:00:06 +0000] "
        '"GET /search?q=\' UNION SELECT * FROM users-- HTTP/1.1" 200 2300',
        {
            "method": "GET",
            "path": "/search",
            "query": "q=' UNION SELECT * FROM users--",
            "status_code": 200,
        },
        id="url_with_spaces_sqli_payload",
    ),
]


@pytest.mark.parametrize("line,expected", VALID_CLF_LINES)
def test_valid_clf_line_parses_correctly(tmp_path, line, expected):
    log_file = tmp_path / "webserver.log"
    log_file.write_text(line + "\n", encoding="utf-8")

    entries = list(WebLogParser().parse(log_file))

    assert len(entries) == 1, f"Expected 1 entry, got {len(entries)}"
    entry = entries[0]
    for field, value in expected.items():
        actual = getattr(entry, field)
        assert actual == value, f"Field {field!r}: expected {value!r}, got {actual!r}"


# ---------------------------------------------------------------------------
# Timestamp specifics
# ---------------------------------------------------------------------------

def test_timestamp_is_naive_datetime(tmp_path):
    """Timezone info must be stripped so auth.log and web timestamps are comparable."""
    line = '192.168.1.1 - - [03/Jul/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 100'
    log_file = tmp_path / "webserver.log"
    log_file.write_text(line + "\n", encoding="utf-8")

    entries = list(WebLogParser().parse(log_file))

    assert entries[0].timestamp.tzinfo is None
    assert entries[0].timestamp == datetime(2025, 7, 3, 10, 0, 1)


# ---------------------------------------------------------------------------
# URL with query — partition correctness
# ---------------------------------------------------------------------------

def test_query_string_split_on_first_question_mark(tmp_path):
    """Path with ?foo=bar correctly splits into path + query."""
    line = '1.2.3.4 - - [03/Jul/2025:12:00:00 +0000] "GET /api/search?q=test&page=2 HTTP/1.1" 200 500'
    log_file = tmp_path / "webserver.log"
    log_file.write_text(line + "\n", encoding="utf-8")

    entries = list(WebLogParser().parse(log_file))

    assert entries[0].path == "/api/search"
    assert entries[0].query == "q=test&page=2"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_blank_lines_silently_skipped(tmp_path):
    good = '1.2.3.4 - - [03/Jul/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 100'
    log_file = tmp_path / "webserver.log"
    log_file.write_text(f"\n{good}\n\n", encoding="utf-8")

    entries = list(WebLogParser().parse(log_file))

    assert len(entries) == 1


def test_malformed_entry_logs_warning_and_is_skipped(tmp_path, caplog):
    """The literal [MALFORMED ENTRY…] line from the actual log is recovered gracefully."""
    good_1 = '192.168.1.1 - - [03/Jul/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234'
    bad    = "[MALFORMED ENTRY - system restart"
    good_2 = '192.168.1.2 - - [03/Jul/2025:10:00:02 +0000] "GET /about.html HTTP/1.1" 200 982'

    log_file = tmp_path / "webserver.log"
    log_file.write_text(f"{good_1}\n{bad}\n{good_2}\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="analyzer.parsers.web_parser"):
        entries = list(WebLogParser().parse(log_file))

    assert len(entries) == 2
    assert entries[0].source_ip == "192.168.1.1"
    assert entries[1].source_ip == "192.168.1.2"

    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("Unrecognised format" in m for m in warning_msgs)
    assert any("webserver.log:2" in m for m in warning_msgs)


def test_multiple_malformed_lines_do_not_stop_processing(tmp_path):
    lines = [
        '10.0.0.1 - - [03/Jul/2025:10:00:01 +0000] "GET /a HTTP/1.1" 200 100',
        "[MALFORMED ENTRY - system restart",
        "this line is also not CLF",
        '10.0.0.2 - - [03/Jul/2025:10:00:03 +0000] "GET /b HTTP/1.1" 200 200',
    ]
    log_file = tmp_path / "webserver.log"
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    entries = list(WebLogParser().parse(log_file))

    assert len(entries) == 2
    assert entries[0].path == "/a"
    assert entries[1].path == "/b"


def test_raw_line_preserved_on_entry(tmp_path):
    """entry.raw must equal the original unmodified log line."""
    line = '1.2.3.4 - - [03/Jul/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 100'
    log_file = tmp_path / "webserver.log"
    log_file.write_text(line + "\n", encoding="utf-8")

    entries = list(WebLogParser().parse(log_file))

    assert entries[0].raw == line
