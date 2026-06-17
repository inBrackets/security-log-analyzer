"""
Tests for PathTraversalRule — traversal detection, severity escalation to
CRITICAL on sensitive-file targets, URL-decode coverage, and stateless
(per-entry) firing behaviour.
"""
from __future__ import annotations

import pytest

from analyzer.models import Severity
from analyzer.rules.path_traversal import PathTraversalRule

ATTACKER = "10.0.0.77"


# ---------------------------------------------------------------------------
# True positives — traversal sequences that must fire
# ---------------------------------------------------------------------------

class TestTraversalDetection:
    @pytest.mark.parametrize("path,query", [
        ("/../../../etc/hosts",         ""),
        ("/files/../../../var/log/syslog", ""),
        ("/static/../../config.yaml",   ""),
        ("/img/..\\..\\.\\windows",     ""),    # backslash traversal
        ("/search",                     "file=../../../../secret.txt"),  # traversal in query
    ])
    def test_traversal_fires_high(self, path, query, make_web):
        rule = PathTraversalRule()
        entry = make_web(path=path, query=query, source_ip=ATTACKER)
        incidents = list(rule.feed(entry))
        assert len(incidents) == 1
        assert incidents[0].severity == Severity.HIGH

    @pytest.mark.parametrize("path,query", [
        ("/../../../etc/passwd",        ""),
        ("/../../../etc/shadow",        ""),
        ("/static/../.ssh/id_rsa",      ""),
        ("/files/../../boot.ini",       ""),
        ("/assets/../win.ini",          ""),
        ("/search",                     "file=../../etc/passwd"),  # sensitive file in query
    ])
    def test_sensitive_target_fires_critical(self, path, query, make_web):
        rule = PathTraversalRule()
        entry = make_web(path=path, query=query, source_ip=ATTACKER)
        incidents = list(rule.feed(entry))
        assert len(incidents) == 1
        assert incidents[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# URL-encoding coverage — decodes before matching
# ---------------------------------------------------------------------------

class TestUrlDecoding:
    def test_percent_encoded_traversal_fires(self, make_web):
        """
        %2e%2e%2f decodes to ../ via unquote_plus — must be detected.
        """
        rule = PathTraversalRule()
        entry = make_web(path="/%2e%2e%2fetc%2fhosts", source_ip=ATTACKER)
        incidents = list(rule.feed(entry))
        assert len(incidents) == 1

    def test_double_encoded_traversal_fires(self, make_web):
        """
        %252e%252e%252f: outer unquote_plus yields %2e%2e%2f, which the
        regex catches as a traversal sequence — defence against double-encoding.
        """
        rule = PathTraversalRule()
        entry = make_web(path="/%252e%252e%252fetc%252fpasswd", source_ip=ATTACKER)
        incidents = list(rule.feed(entry))
        assert len(incidents) == 1

    def test_plus_encoded_spaces_in_query_do_not_break_detection(self, make_web):
        rule = PathTraversalRule()
        entry = make_web(path="/search", query="file=../../../etc/shadow",
                         source_ip=ATTACKER)
        incidents = list(rule.feed(entry))
        assert incidents[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# False positives — clean paths that must not fire
# ---------------------------------------------------------------------------

class TestCleanPaths:
    @pytest.mark.parametrize("path", [
        "/api/users/1",
        "/static/style.css",
        "/files/report.pdf",
        "/search",
        "/admin/dashboard",
        "/v2/endpoint",
    ])
    def test_clean_path_does_not_fire(self, path, make_web):
        rule = PathTraversalRule()
        incidents = list(rule.feed(make_web(path=path)))
        assert not incidents

    def test_dotdot_without_trailing_slash_does_not_fire(self, make_web):
        """
        '/files/..' ends with '..' but has no following slash — the traversal
        regex requires '../' or '..\' so this does not fire.
        """
        rule = PathTraversalRule()
        incidents = list(rule.feed(make_web(path="/files/..")))
        assert not incidents


# ---------------------------------------------------------------------------
# Stateless behaviour — no per-IP deduplication
# ---------------------------------------------------------------------------

class TestStateless:
    def test_every_matching_entry_produces_an_incident(self, make_web):
        """PathTraversalRule has no _alerted guard — it fires on each entry."""
        rule = PathTraversalRule()
        incidents = []
        for _ in range(3):
            incidents.extend(rule.feed(make_web(path="/../../../etc/hosts",
                                                 source_ip=ATTACKER)))
        assert len(incidents) == 3

    def test_auth_entries_are_ignored(self, make_auth):
        rule = PathTraversalRule()
        assert not list(rule.feed(make_auth()))


# ---------------------------------------------------------------------------
# Incident attributes
# ---------------------------------------------------------------------------

class TestIncidentAttributes:
    def _incident(self, make_web, *, path="/../../../etc/hosts", query=""):
        rule = PathTraversalRule()
        return list(rule.feed(make_web(path=path, query=query,
                                       source_ip=ATTACKER)))[0]

    def test_rule_name(self, make_web):
        assert self._incident(make_web).rule_name == "path_traversal"

    def test_source_ip_propagated(self, make_web):
        assert self._incident(make_web).source_ip == ATTACKER

    def test_evidence_contains_decoded_target(self, make_web):
        inc = self._incident(make_web)
        assert any("Decoded target:" in line for line in inc.evidence)

    def test_evidence_contains_raw_line(self, make_web):
        inc = self._incident(make_web)
        assert len(inc.evidence) == 2
        assert inc.evidence[0] == "[test raw line]"

    def test_description_contains_path(self, make_web):
        path = "/../../../etc/hosts"
        inc = self._incident(make_web, path=path)
        assert path in inc.description
