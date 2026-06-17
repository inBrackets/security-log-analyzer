"""
Tests for SQLInjectionRule — weighted signal scoring, severity mapping,
and false-positive prevention (O'Brien is not SQL injection).
"""
from __future__ import annotations

from urllib.parse import unquote_plus

import pytest

from analyzer.models import Severity
from analyzer.rules.sql_injection import SQLInjectionRule, _SIGNALS


# ---------------------------------------------------------------------------
# True-positive cases: these MUST fire an incident
# ---------------------------------------------------------------------------

TRUE_POSITIVES = [
    pytest.param(
        "q=' UNION SELECT * FROM users--", 200, Severity.CRITICAL,
        id="union_select_200",
    ),
    pytest.param(
        "q=' UNION SELECT * FROM users--", 404, Severity.HIGH,
        id="union_select_404",
    ),
    pytest.param(
        "q=1; DROP TABLE users--", 200, Severity.CRITICAL,
        id="drop_table_stacked_200",
    ),
    pytest.param(
        "q=1; DROP TABLE users--", 500, Severity.HIGH,
        id="drop_table_stacked_500",
    ),
    pytest.param(
        "q=' OR 1=1--", 200, Severity.CRITICAL,
        id="or_tautology_200",
    ),
    pytest.param(
        "q=admin'--", 403, Severity.HIGH,
        id="string_terminator_comment_403",
    ),
    pytest.param(
        "id=1 UNION SELECT null,null--", 200, Severity.CRITICAL,
        id="union_select_nulls",
    ),
    pytest.param(
        "q=UNION%20SELECT%20*%20FROM%20users", 200, Severity.CRITICAL,
        id="url_encoded_union_select",
    ),
    pytest.param(
        "q=1+UNION+SELECT+*+FROM+users", 200, Severity.CRITICAL,
        id="plus_encoded_union_select",
    ),
    pytest.param(
        "search=test' AND 1=1--", 200, Severity.CRITICAL,
        id="and_tautology",
    ),
    pytest.param(
        "q='; exec(xp_cmdshell('ls'))--", 500, Severity.HIGH,
        id="exec_xp_cmdshell",
    ),
    pytest.param(
        "q=1 AND information_schema.tables--", 200, Severity.CRITICAL,
        id="information_schema",
    ),
]


@pytest.mark.parametrize("query,status_code,expected_severity", TRUE_POSITIVES)
def test_sql_injection_true_positive(query, status_code, expected_severity, make_web):
    rule = SQLInjectionRule()
    entry = make_web(query=query, status_code=status_code)

    incidents = list(rule.feed(entry))

    assert len(incidents) == 1, (
        f"Expected 1 incident for query {query!r}, got {len(incidents)}"
    )
    assert incidents[0].severity == expected_severity
    assert incidents[0].rule_name == "sql_injection"
    assert incidents[0].source_ip == entry.source_ip


# ---------------------------------------------------------------------------
# False-positive cases: these must NOT fire (score below threshold)
# ---------------------------------------------------------------------------

FALSE_POSITIVES = [
    pytest.param("q=O'Brien",                     id="name_obrien"),
    pytest.param("q=O'Brien's laptop",             id="name_obrien_possessive"),
    pytest.param("q=it's a fine day",              id="apostrophe_in_phrase"),
    pytest.param("q=McDonald's",                   id="name_mcdonalds"),
    pytest.param("q=select",                       id="select_keyword_alone"),
    pytest.param("q=drop",                         id="drop_keyword_alone"),
    pytest.param("q=laptop",                       id="plain_english_word"),
    pytest.param("q=1=1",                          id="equality_without_or"),
    pytest.param("q=hello--world",                 id="hyphens_in_word"),
    pytest.param("q=",                             id="empty_value"),
    pytest.param("",                               id="no_query_string"),
    pytest.param("q=search%20for%20things",        id="url_encoded_safe"),
    pytest.param("q=a+b+c",                        id="plus_encoded_safe"),
]


@pytest.mark.parametrize("query", FALSE_POSITIVES)
def test_sql_injection_no_false_positive(query, make_web):
    rule = SQLInjectionRule()
    entry = make_web(query=query, status_code=200)

    incidents = list(rule.feed(entry))

    assert not incidents, (
        f"False positive for query {query!r}. "
        f"Incident: {incidents[0].evidence if incidents else 'n/a'}"
    )


# ---------------------------------------------------------------------------
# O'Brien white-box score verification
# ---------------------------------------------------------------------------

def test_obrien_scores_exactly_zero():
    """No signal should fire on an apostrophe in a name with no SQL structure."""
    decoded = unquote_plus("q=O'Brien")
    fired = [s.name for s in _SIGNALS if s.pattern.search(decoded)]
    assert fired == [], f"Unexpected signals fired: {fired}"


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status_code,expected_severity", [
    (200, Severity.CRITICAL),
    (201, Severity.HIGH),
    (301, Severity.HIGH),
    (400, Severity.HIGH),
    (403, Severity.HIGH),
    (404, Severity.HIGH),
    (500, Severity.HIGH),
    (503, Severity.HIGH),
])
def test_severity_depends_on_response_code(status_code, expected_severity, make_web):
    """CRITICAL only when server returned 200; otherwise HIGH."""
    rule = SQLInjectionRule()
    entry = make_web(query="q=' UNION SELECT * FROM users--", status_code=status_code)

    incidents = list(rule.feed(entry))

    assert len(incidents) == 1
    assert incidents[0].severity == expected_severity


# ---------------------------------------------------------------------------
# Evidence content
# ---------------------------------------------------------------------------

def test_incident_evidence_contains_score_and_signals(make_web):
    rule = SQLInjectionRule()
    entry = make_web(query="q=' UNION SELECT * FROM users--", status_code=200)

    incidents = list(rule.feed(entry))

    evidence_text = " ".join(incidents[0].evidence)
    assert "Score:" in evidence_text
    assert "UNION SELECT" in evidence_text


def test_incident_evidence_contains_decoded_query(make_web):
    rule = SQLInjectionRule()
    entry = make_web(query="q=UNION%20SELECT%20*%20FROM%20users", status_code=200)

    incidents = list(rule.feed(entry))

    evidence_text = " ".join(incidents[0].evidence)
    assert "UNION SELECT" in evidence_text  # decoded form appears in evidence


# ---------------------------------------------------------------------------
# Entry type gating
# ---------------------------------------------------------------------------

def test_auth_entries_are_ignored(make_auth):
    """SQLInjectionRule only applies to WebEntry instances."""
    rule = SQLInjectionRule()
    incidents = list(rule.feed(make_auth()))
    assert not incidents


def test_web_entry_with_no_query_is_ignored(make_web):
    rule = SQLInjectionRule()
    entry = make_web(query="", path="/index.html", status_code=200)
    incidents = list(rule.feed(entry))
    assert not incidents


# ---------------------------------------------------------------------------
# Custom threshold
# ---------------------------------------------------------------------------

def test_custom_threshold_raises_bar(make_web):
    """With a higher threshold, previously-triggering payloads may not fire."""
    rule = SQLInjectionRule(threshold=50)  # impossibly high
    entry = make_web(query="q=' UNION SELECT * FROM users--", status_code=200)
    incidents = list(rule.feed(entry))
    assert not incidents
