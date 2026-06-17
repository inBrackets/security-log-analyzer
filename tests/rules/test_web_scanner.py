"""
Tests for WebScannerRule — distinct-path threshold, sliding-window eviction,
status-code gating, and deduplication.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from analyzer.models import Severity
from analyzer.rules.web_scanner import WebScannerRule
from tests.conftest import BASE_TS

ATTACKER = "172.16.0.20"
OTHER_IP = "203.0.113.9"


# ---------------------------------------------------------------------------
# Threshold behaviour
# ---------------------------------------------------------------------------

class TestThreshold:
    @pytest.mark.parametrize("num_paths,expect_fire", [
        (3, False),
        (4, False),
        (5, True),   # exactly at threshold
        (7, True),   # above threshold
    ])
    def test_fires_at_distinct_path_threshold(self, num_paths, expect_fire, make_web):
        rule = WebScannerRule(threshold=5, window_seconds=60)
        incidents = []
        for i in range(num_paths):
            entry = make_web(
                source_ip=ATTACKER, path=f"/probe/{i}",
                status_code=404, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert bool(incidents) == expect_fire

    def test_repeated_same_path_does_not_count_as_distinct(self, make_web):
        """Hammering the same 404 path should not trigger the scanner rule."""
        rule = WebScannerRule(threshold=5, window_seconds=60)
        incidents = []
        for i in range(10):
            entry = make_web(
                source_ip=ATTACKER, path="/login",
                status_code=404, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert not incidents  # same path 10 times — only 1 distinct path

    def test_mix_of_403_and_404_both_contribute(self, make_web):
        rule = WebScannerRule(threshold=4, window_seconds=60)
        codes = [403, 404, 403, 404]
        incidents = []
        for i, code in enumerate(codes):
            entry = make_web(
                source_ip=ATTACKER, path=f"/path/{i}",
                status_code=code, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert any(inc.severity == Severity.HIGH for inc in incidents)

    def test_fires_exactly_once_per_ip(self, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(10):
            entry = make_web(
                source_ip=ATTACKER, path=f"/probe/{i}",
                status_code=404, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert sum(1 for inc in incidents if inc.severity == Severity.HIGH) == 1

    def test_different_ips_tracked_independently(self, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            for ip in [ATTACKER, OTHER_IP]:
                entry = make_web(
                    source_ip=ip, path=f"/probe/{i}",
                    status_code=404, timestamp=BASE_TS + timedelta(seconds=i),
                )
                incidents.extend(rule.feed(entry))

        fired_ips = {inc.source_ip for inc in incidents}
        assert fired_ips == {ATTACKER, OTHER_IP}


# ---------------------------------------------------------------------------
# Sliding-window eviction
# ---------------------------------------------------------------------------

class TestWindow:
    def test_paths_outside_window_not_counted(self, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)

        # Two distinct paths inside window
        for i in range(2):
            entry = make_web(
                source_ip=ATTACKER, path=f"/old/{i}",
                status_code=404, timestamp=BASE_TS + timedelta(seconds=i),
            )
            list(rule.feed(entry))

        # Third distinct path — but 120s later, old paths expired
        entry = make_web(
            source_ip=ATTACKER, path="/new/path",
            status_code=404, timestamp=BASE_TS + timedelta(seconds=120),
        )
        incidents = list(rule.feed(entry))

        assert not incidents  # only 1 distinct path in current window

    def test_paths_within_window_all_counted(self, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, path=f"/probe/{i}",
                status_code=404, timestamp=BASE_TS + timedelta(seconds=i * 15),
            )
            incidents.extend(rule.feed(entry))

        assert any(inc.severity == Severity.HIGH for inc in incidents)


# ---------------------------------------------------------------------------
# Status-code gating
# ---------------------------------------------------------------------------

class TestStatusCodeGating:
    @pytest.mark.parametrize("status_code", [200, 201, 301, 302, 401, 500, 503])
    def test_non_403_404_codes_are_ignored(self, status_code, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(5):
            entry = make_web(
                source_ip=ATTACKER, path=f"/probe/{i}",
                status_code=status_code, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert not incidents

    def test_403_triggers(self, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, path=f"/admin/{i}",
                status_code=403, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert any(inc.severity == Severity.HIGH for inc in incidents)

    def test_404_triggers(self, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, path=f"/missing/{i}",
                status_code=404, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert any(inc.severity == Severity.HIGH for inc in incidents)


# ---------------------------------------------------------------------------
# Entry-type gating
# ---------------------------------------------------------------------------

def test_auth_entries_are_ignored(make_auth):
    rule = WebScannerRule(threshold=3, window_seconds=60)
    incidents = list(rule.feed(make_auth()))
    assert not incidents


# ---------------------------------------------------------------------------
# Incident attributes
# ---------------------------------------------------------------------------

class TestIncidentAttributes:
    def test_severity_is_high(self, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, path=f"/probe/{i}",
                status_code=404, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        inc = next(i for i in incidents if i.severity == Severity.HIGH)
        assert inc.severity == Severity.HIGH

    def test_count_reflects_distinct_paths(self, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)
        # 4 requests to 3 distinct paths (one repeated)
        paths = ["/a", "/b", "/a", "/c"]
        incidents = []
        for i, path in enumerate(paths):
            entry = make_web(
                source_ip=ATTACKER, path=path,
                status_code=404, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        inc = next(i for i in incidents if i.severity == Severity.HIGH)
        assert inc.count == 3  # 3 distinct paths, not 4 total requests

    def test_evidence_contains_raw_lines(self, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, path=f"/probe/{i}",
                status_code=404, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        inc = next(i for i in incidents if i.severity == Severity.HIGH)
        assert len(inc.evidence) == 3
        assert all(isinstance(line, str) for line in inc.evidence)

    def test_rule_name_and_source_ip(self, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, path=f"/probe/{i}",
                status_code=404, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        inc = next(i for i in incidents if i.severity == Severity.HIGH)
        assert inc.rule_name == "web_scanner"
        assert inc.source_ip == ATTACKER

    def test_description_mentions_distinct_count_and_window(self, make_web):
        rule = WebScannerRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, path=f"/probe/{i}",
                status_code=404, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        inc = next(i for i in incidents if i.severity == Severity.HIGH)
        assert "3" in inc.description
        assert "60" in inc.description
