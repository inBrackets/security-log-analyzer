"""
Tests for RapidRequestRule — burst threshold, per-endpoint isolation,
sliding-window eviction, HTTP method gating, and status-code agnosticism.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from analyzer.models import Severity
from analyzer.rules.rapid_request import RapidRequestRule
from tests.conftest import BASE_TS

ATTACKER = "10.0.0.99"
OTHER_IP  = "203.0.113.9"
ENDPOINT  = "/api/checkout"


# ---------------------------------------------------------------------------
# Threshold behaviour — fires when count EXCEEDS threshold (i.e., > N)
# ---------------------------------------------------------------------------

class TestThreshold:
    @pytest.mark.parametrize("num_requests,expect_fire", [
        (2, False),
        (3, False),   # exactly at threshold — must not fire
        (4, True),    # first request that exceeds threshold
        (8, True),
    ])
    def test_fires_when_count_exceeds_threshold(self, num_requests, expect_fire, make_web):
        rule = RapidRequestRule(threshold=3, window_seconds=10)
        incidents = []
        for i in range(num_requests):
            entry = make_web(
                method="POST", path=ENDPOINT, source_ip=ATTACKER,
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert bool(incidents) == expect_fire

    def test_fires_exactly_once_per_endpoint(self, make_web):
        rule = RapidRequestRule(threshold=3, window_seconds=10)
        incidents = []
        for i in range(12):
            entry = make_web(
                method="POST", path=ENDPOINT, source_ip=ATTACKER,
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert sum(1 for inc in incidents if inc.severity == Severity.HIGH) == 1

    def test_different_ips_tracked_independently(self, make_web):
        rule = RapidRequestRule(threshold=3, window_seconds=10)
        incidents = []
        for ip in [ATTACKER, OTHER_IP]:
            for i in range(4):
                entry = make_web(
                    method="POST", path=ENDPOINT, source_ip=ip,
                    timestamp=BASE_TS + timedelta(seconds=i),
                )
                incidents.extend(rule.feed(entry))

        fired_ips = {inc.source_ip for inc in incidents}
        assert fired_ips == {ATTACKER, OTHER_IP}


# ---------------------------------------------------------------------------
# Per-endpoint isolation — (IP, path) pairs are tracked independently
# ---------------------------------------------------------------------------

class TestEndpointIsolation:
    def test_different_paths_do_not_pool_together(self, make_web):
        """Requests to /api/a and /api/b each have their own counter."""
        rule = RapidRequestRule(threshold=3, window_seconds=10)
        incidents = []
        for path in ("/api/a", "/api/b"):
            for i in range(2):  # 2 per path — total 4, but only 2 per endpoint
                entry = make_web(
                    method="POST", path=path, source_ip=ATTACKER,
                    timestamp=BASE_TS + timedelta(seconds=i),
                )
                incidents.extend(rule.feed(entry))

        assert not incidents  # 2 requests per endpoint, threshold is 3

    def test_fires_independently_per_endpoint(self, make_web):
        """Same IP bursting two different endpoints produces two incidents."""
        rule = RapidRequestRule(threshold=3, window_seconds=10)
        incidents = []
        for path in ("/api/checkout", "/api/transfer"):
            for i in range(4):  # 4 per path — exceeds threshold=3
                entry = make_web(
                    method="POST", path=path, source_ip=ATTACKER,
                    timestamp=BASE_TS + timedelta(seconds=i),
                )
                incidents.extend(rule.feed(entry))

        assert len(incidents) == 2
        fired_paths = {inc.description for inc in incidents}
        assert any("/api/checkout" in d for d in fired_paths)
        assert any("/api/transfer" in d for d in fired_paths)


# ---------------------------------------------------------------------------
# Sliding-window eviction
# ---------------------------------------------------------------------------

class TestWindow:
    def test_requests_outside_window_not_counted(self, make_web):
        rule = RapidRequestRule(threshold=3, window_seconds=2)

        # 3 requests within a 2s window
        for i in range(3):
            entry = make_web(
                method="POST", path=ENDPOINT, source_ip=ATTACKER,
                timestamp=BASE_TS + timedelta(milliseconds=i * 500),
            )
            list(rule.feed(entry))

        # 5s later: another burst — the first 3 have expired
        for i in range(3):
            entry = make_web(
                method="POST", path=ENDPOINT, source_ip=ATTACKER,
                timestamp=BASE_TS + timedelta(seconds=5, milliseconds=i * 500),
            )
            incidents = list(rule.feed(entry))
            # Each call has at most 1-3 events in the new window — never > 3
            assert not incidents

    def test_requests_spanning_boundary_are_correctly_counted(self, make_web):
        """Events exactly at the window boundary (t_current - t_old == window) are retained."""
        rule = RapidRequestRule(threshold=1, window_seconds=2)

        # Two requests exactly 2s apart: eviction threshold is strictly > window,
        # so the older event is retained and the count becomes 2 > 1 → fires.
        entry1 = make_web(method="POST", path=ENDPOINT, source_ip=ATTACKER,
                           timestamp=BASE_TS)
        entry2 = make_web(method="POST", path=ENDPOINT, source_ip=ATTACKER,
                           timestamp=BASE_TS + timedelta(seconds=2))
        list(rule.feed(entry1))
        incidents = list(rule.feed(entry2))

        assert any(inc.severity == Severity.HIGH for inc in incidents)


# ---------------------------------------------------------------------------
# HTTP method gating — only POST requests count
# ---------------------------------------------------------------------------

class TestMethodGating:
    @pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH", "HEAD"])
    def test_non_post_methods_are_ignored(self, method, make_web):
        rule = RapidRequestRule(threshold=3, window_seconds=10)
        incidents = []
        for i in range(10):
            entry = make_web(
                method=method, path=ENDPOINT, source_ip=ATTACKER,
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert not incidents

    def test_only_post_triggers(self, make_web):
        rule = RapidRequestRule(threshold=3, window_seconds=10)
        incidents = []
        for i in range(4):
            entry = make_web(
                method="POST", path=ENDPOINT, source_ip=ATTACKER,
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert any(inc.severity == Severity.HIGH for inc in incidents)


# ---------------------------------------------------------------------------
# Status-code agnosticism — rule fires on request pattern, not response code
# ---------------------------------------------------------------------------

class TestStatusCodeAgnostic:
    @pytest.mark.parametrize("status_code", [200, 201, 400, 401, 429, 500, 503])
    def test_fires_regardless_of_status_code(self, status_code, make_web):
        """The 429 case is the canonical correlation scenario (rate-limiter response)."""
        rule = RapidRequestRule(threshold=3, window_seconds=10)
        incidents = []
        for i in range(4):
            entry = make_web(
                method="POST", path=ENDPOINT, source_ip=ATTACKER,
                status_code=status_code, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert any(inc.severity == Severity.HIGH for inc in incidents)


# ---------------------------------------------------------------------------
# Entry-type gating
# ---------------------------------------------------------------------------

def test_auth_entries_are_ignored(make_auth):
    rule = RapidRequestRule(threshold=3, window_seconds=10)
    assert not list(rule.feed(make_auth()))


def test_web_get_entry_is_ignored(make_web):
    rule = RapidRequestRule(threshold=3, window_seconds=10)
    assert not list(rule.feed(make_web(method="GET", path=ENDPOINT)))


# ---------------------------------------------------------------------------
# Incident attributes
# ---------------------------------------------------------------------------

class TestIncidentAttributes:
    def _fire(self, make_web, *, threshold=3):
        rule = RapidRequestRule(threshold=threshold, window_seconds=10)
        incidents = []
        for i in range(threshold + 1):
            entry = make_web(
                method="POST", path=ENDPOINT, source_ip=ATTACKER,
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))
        return next(inc for inc in incidents if inc.severity == Severity.HIGH)

    def test_severity_is_high(self, make_web):
        inc = self._fire(make_web)
        assert inc.severity == Severity.HIGH

    def test_rule_name_and_source_ip(self, make_web):
        inc = self._fire(make_web)
        assert inc.rule_name == "rapid_request"
        assert inc.source_ip == ATTACKER

    def test_count_equals_requests_in_window(self, make_web):
        inc = self._fire(make_web, threshold=3)
        assert inc.count == 4  # threshold=3 → fires at 4th request

    def test_evidence_contains_raw_lines(self, make_web):
        inc = self._fire(make_web, threshold=3)
        assert len(inc.evidence) == 4
        assert all(isinstance(line, str) for line in inc.evidence)

    def test_description_mentions_path_and_window(self, make_web):
        rule = RapidRequestRule(threshold=3, window_seconds=2)
        incidents = []
        for i in range(4):
            entry = make_web(
                method="POST", path=ENDPOINT, source_ip=ATTACKER,
                timestamp=BASE_TS + timedelta(milliseconds=i * 400),
            )
            incidents.extend(rule.feed(entry))

        inc = next(i for i in incidents if i.severity == Severity.HIGH)
        assert ENDPOINT in inc.description
        assert "2" in inc.description  # window_seconds appears in description
