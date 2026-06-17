"""
Tests for WebBruteForceRule — login-path filtering, threshold detection,
CRITICAL escalation on POST 200, and IPTracker integration.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from analyzer.models import Severity
from analyzer.rules.web_brute_force import WebBruteForceRule
from tests.conftest import BASE_TS
ATTACKER = "10.0.0.50"


# ---------------------------------------------------------------------------
# Path filtering — only login endpoints are tracked
# ---------------------------------------------------------------------------

class TestPathFiltering:
    @pytest.mark.parametrize("path,expect_incident", [
        ("/login",       True),
        ("/signin",      True),
        ("/auth",        True),
        ("/session",     True),
        ("/wp-login.php", True),
        ("/login/reset", True),   # substring match
        ("/api/users",   False),
        ("/dashboard",   False),
        ("/search",      False),
        ("/index.html",  False),
    ])
    def test_only_login_paths_are_tracked(self, path, expect_incident, make_web):
        rule = WebBruteForceRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, method="POST", path=path,
                status_code=401, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert bool(incidents) == expect_incident, (
            f"Path {path!r}: expected_incident={expect_incident}, got={bool(incidents)}"
        )


# ---------------------------------------------------------------------------
# Threshold behaviour
# ---------------------------------------------------------------------------

class TestThreshold:
    @pytest.mark.parametrize("num_failures,expect_high", [
        (1, False),
        (2, False),
        (3, True),   # exactly at threshold
        (4, True),   # above threshold
    ])
    def test_high_fires_at_threshold(self, num_failures, expect_high, make_web):
        rule = WebBruteForceRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(num_failures):
            entry = make_web(
                source_ip=ATTACKER, method="POST", path="/login",
                status_code=401, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        high_incidents = [inc for inc in incidents if inc.severity == Severity.HIGH]
        assert bool(high_incidents) == expect_high

    def test_high_fires_exactly_once_per_ip(self, make_web):
        rule = WebBruteForceRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(8):
            entry = make_web(
                source_ip=ATTACKER, method="POST", path="/login",
                status_code=401, timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        high_count = sum(1 for inc in incidents if inc.severity == Severity.HIGH)
        assert high_count == 1

    def test_failures_outside_window_not_counted(self, make_web):
        rule = WebBruteForceRule(threshold=3, window_seconds=60)
        for i in range(2):
            entry = make_web(
                source_ip=ATTACKER, method="POST", path="/login",
                status_code=401, timestamp=BASE_TS + timedelta(seconds=i),
            )
            list(rule.feed(entry))

        # Third failure after a 120s gap — the first two have expired
        entry = make_web(
            source_ip=ATTACKER, method="POST", path="/login",
            status_code=401, timestamp=BASE_TS + timedelta(seconds=120),
        )
        incidents = list(rule.feed(entry))

        assert not incidents


# ---------------------------------------------------------------------------
# CRITICAL escalation on POST 200
# ---------------------------------------------------------------------------

class TestSuccessEscalation:
    def test_post_200_after_failures_fires_critical(self, make_web):
        rule = WebBruteForceRule(threshold=3, window_seconds=60)
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, method="POST", path="/login",
                status_code=401, timestamp=BASE_TS + timedelta(seconds=i),
            )
            list(rule.feed(entry))

        success = make_web(
            source_ip=ATTACKER, method="POST", path="/login",
            status_code=200, timestamp=BASE_TS + timedelta(seconds=5),
        )
        incidents = list(rule.feed(success))

        assert any(inc.severity == Severity.CRITICAL for inc in incidents)

    def test_get_200_after_failures_does_not_fire_critical(self, make_web):
        """Only POST 200 constitutes a successful brute-force login; GET 200 does not."""
        rule = WebBruteForceRule(threshold=3, window_seconds=60)
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, method="POST", path="/login",
                status_code=401, timestamp=BASE_TS + timedelta(seconds=i),
            )
            list(rule.feed(entry))

        get_success = make_web(
            source_ip=ATTACKER, method="GET", path="/login",
            status_code=200, timestamp=BASE_TS + timedelta(seconds=5),
        )
        incidents = list(rule.feed(get_success))

        assert not any(inc.severity == Severity.CRITICAL for inc in incidents)

    def test_post_200_with_no_prior_failures_is_silent(self, make_web):
        rule = WebBruteForceRule(threshold=3, window_seconds=60)
        success = make_web(
            source_ip=ATTACKER, method="POST", path="/login", status_code=200,
        )
        incidents = list(rule.feed(success))
        assert not incidents

    def test_success_clears_buffer_for_future_attacks(self, make_web):
        """After a CRITICAL, the failure buffer is cleared and the IP can be re-alerted."""
        rule = WebBruteForceRule(threshold=3, window_seconds=60)
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, method="POST", path="/login",
                status_code=401, timestamp=BASE_TS + timedelta(seconds=i),
            )
            list(rule.feed(entry))

        success = make_web(
            source_ip=ATTACKER, method="POST", path="/login",
            status_code=200, timestamp=BASE_TS + timedelta(seconds=5),
        )
        list(rule.feed(success))

        # New wave of attacks after the reset
        new_incidents = []
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, method="POST", path="/login",
                status_code=401, timestamp=BASE_TS + timedelta(seconds=10 + i),
            )
            new_incidents.extend(rule.feed(entry))

        assert any(inc.severity == Severity.HIGH for inc in new_incidents)

    def test_critical_evidence_includes_all_evidence(self, make_web):
        rule = WebBruteForceRule(threshold=3, window_seconds=60)
        for i in range(3):
            entry = make_web(
                source_ip=ATTACKER, method="POST", path="/login",
                status_code=401, timestamp=BASE_TS + timedelta(seconds=i),
            )
            list(rule.feed(entry))

        success = make_web(
            source_ip=ATTACKER, method="POST", path="/login",
            status_code=200, timestamp=BASE_TS + timedelta(seconds=5),
        )
        incidents = list(rule.feed(success))

        critical = next(inc for inc in incidents if inc.severity == Severity.CRITICAL)
        assert critical.count == 4  # 3 failures + 1 success
        assert len(critical.evidence) == 4


# ---------------------------------------------------------------------------
# Entry type gating
# ---------------------------------------------------------------------------

def test_auth_entries_are_ignored_by_web_rule(make_auth):
    rule = WebBruteForceRule(threshold=3, window_seconds=60)
    incidents = list(rule.feed(make_auth()))
    assert not incidents


def test_non_401_non_200_status_codes_are_ignored(make_web):
    """Status codes other than 401 (failure) or 200 POST (success) don't affect state."""
    rule = WebBruteForceRule(threshold=3, window_seconds=60)
    incidents = []
    for code in (200, 302, 403, 404, 500):  # 200 is GET here, not a POST success trigger
        entry = make_web(
            source_ip=ATTACKER, method="GET", path="/login", status_code=code,
        )
        incidents.extend(rule.feed(entry))

    assert not incidents
