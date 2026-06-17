"""
Tests for SSHBruteForceRule — threshold detection, sliding-window eviction,
CRITICAL escalation on success, and IPTracker integration.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from analyzer.models import Severity
from analyzer.rules.ip_tracker import IPTracker
from analyzer.rules.ssh_brute_force import SSHBruteForceRule

BASE_TS = datetime(2025, 7, 3, 10, 0, 0)
ATTACKER = "10.0.0.50"
OTHER_IP = "203.0.113.9"


# ---------------------------------------------------------------------------
# Threshold behaviour
# ---------------------------------------------------------------------------

class TestThreshold:
    @pytest.mark.parametrize("num_failures,expect_high", [
        (1, False),
        (2, False),
        (3, True),   # exactly at threshold
        (5, True),   # above threshold
    ])
    def test_high_fires_at_threshold(self, num_failures, expect_high, make_auth):
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(num_failures):
            entry = make_auth(
                source_ip=ATTACKER, event_type="failed_password",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        high_incidents = [inc for inc in incidents if inc.severity == Severity.HIGH]
        assert bool(high_incidents) == expect_high

    def test_high_fires_exactly_once_per_ip(self, make_auth):
        """Subsequent failures beyond threshold must not produce duplicate HIGH alerts."""
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(8):  # 2.5× the threshold
            entry = make_auth(
                source_ip=ATTACKER, event_type="failed_password",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        high_count = sum(1 for inc in incidents if inc.severity == Severity.HIGH)
        assert high_count == 1

    def test_different_ips_tracked_independently(self, make_auth):
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            for ip in [ATTACKER, OTHER_IP]:
                entry = make_auth(
                    source_ip=ip, event_type="failed_password",
                    timestamp=BASE_TS + timedelta(seconds=i),
                )
                incidents.extend(rule.feed(entry))

        high_ips = {inc.source_ip for inc in incidents if inc.severity == Severity.HIGH}
        assert high_ips == {ATTACKER, OTHER_IP}

    def test_high_incident_attributes(self, make_auth):
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            entry = make_auth(
                source_ip=ATTACKER, event_type="failed_password",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        high = next(inc for inc in incidents if inc.severity == Severity.HIGH)
        assert high.source_ip == ATTACKER
        assert high.rule_name == "ssh_brute_force"
        assert high.count == 3
        assert len(high.evidence) == 3


# ---------------------------------------------------------------------------
# Sliding-window eviction
# ---------------------------------------------------------------------------

class TestWindow:
    def test_failures_older_than_window_are_not_counted(self, make_auth):
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        # Two failures inside window
        for i in range(2):
            entry = make_auth(
                source_ip=ATTACKER, event_type="failed_password",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            list(rule.feed(entry))

        # Third failure after a 120s gap — the first two have expired
        entry = make_auth(
            source_ip=ATTACKER, event_type="failed_password",
            timestamp=BASE_TS + timedelta(seconds=120),
        )
        incidents = list(rule.feed(entry))

        assert not incidents  # only 1 failure in the current window

    def test_failures_within_window_all_counted(self, make_auth):
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            entry = make_auth(
                source_ip=ATTACKER, event_type="failed_password",
                timestamp=BASE_TS + timedelta(seconds=i * 15),  # 0s, 15s, 30s — all within 60s
            )
            incidents.extend(rule.feed(entry))

        assert any(inc.severity == Severity.HIGH for inc in incidents)


# ---------------------------------------------------------------------------
# CRITICAL escalation on subsequent successful login
# ---------------------------------------------------------------------------

class TestSuccessEscalation:
    def test_success_after_threshold_failures_fires_critical(self, make_auth):
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        incidents = []
        for i in range(3):
            entry = make_auth(
                source_ip=ATTACKER, event_type="failed_password",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        success = make_auth(
            source_ip=ATTACKER, event_type="accepted_password",
            timestamp=BASE_TS + timedelta(seconds=10),
        )
        incidents.extend(rule.feed(success))

        severities = {inc.severity for inc in incidents}
        assert Severity.HIGH in severities
        assert Severity.CRITICAL in severities

    def test_success_with_no_prior_failures_is_silent(self, make_auth):
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        success = make_auth(source_ip=ATTACKER, event_type="accepted_password")
        incidents = list(rule.feed(success))
        assert not incidents

    def test_success_with_one_prior_failure_fires_critical(self, make_auth):
        """Even a single prior failure + success counts as a brute-force success."""
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        failure = make_auth(source_ip=ATTACKER, event_type="failed_password",
                            timestamp=BASE_TS)
        list(rule.feed(failure))

        success = make_auth(source_ip=ATTACKER, event_type="accepted_password",
                            timestamp=BASE_TS + timedelta(seconds=5))
        incidents = list(rule.feed(success))

        assert any(inc.severity == Severity.CRITICAL for inc in incidents)

    def test_critical_evidence_includes_failures_and_success(self, make_auth):
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        for i in range(3):
            entry = make_auth(
                source_ip=ATTACKER, event_type="failed_password",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            list(rule.feed(entry))

        success = make_auth(source_ip=ATTACKER, event_type="accepted_password",
                            timestamp=BASE_TS + timedelta(seconds=5))
        incidents = list(rule.feed(success))

        critical = next(inc for inc in incidents if inc.severity == Severity.CRITICAL)
        assert critical.count == 4            # 3 failures + 1 success
        assert len(critical.evidence) == 4

    def test_success_clears_buffer_for_future_attacks(self, make_auth):
        """After CRITICAL fires and buffer is cleared, new failures should trigger HIGH again."""
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        for i in range(3):
            entry = make_auth(
                source_ip=ATTACKER, event_type="failed_password",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            list(rule.feed(entry))

        success = make_auth(source_ip=ATTACKER, event_type="accepted_password",
                            timestamp=BASE_TS + timedelta(seconds=5))
        list(rule.feed(success))

        # Fresh attack after reset
        new_incidents = []
        for i in range(3):
            entry = make_auth(
                source_ip=ATTACKER, event_type="failed_password",
                timestamp=BASE_TS + timedelta(seconds=10 + i),
            )
            new_incidents.extend(rule.feed(entry))

        assert any(inc.severity == Severity.HIGH for inc in new_incidents)

    def test_success_fires_critical_even_when_failures_outside_window(self, make_auth):
        """
        _handle_success does NOT evict the buffer — it checks only whether the deque
        is non-empty.  Any prior failure from the same IP triggers a CRITICAL, even if
        the failures occurred before the current sliding window.  This is a deliberate
        design trade-off: suspicious logins are never silently dropped.
        """
        rule = SSHBruteForceRule(threshold=3, window_seconds=60)
        for i in range(2):
            entry = make_auth(
                source_ip=ATTACKER, event_type="failed_password",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            list(rule.feed(entry))

        # Success arrives 200s later — failures are beyond the 60s window, but
        # the buffer was never evicted (eviction only runs on new *failures*)
        success = make_auth(source_ip=ATTACKER, event_type="accepted_password",
                            timestamp=BASE_TS + timedelta(seconds=200))
        incidents = list(rule.feed(success))

        assert any(inc.severity == Severity.CRITICAL for inc in incidents)


# ---------------------------------------------------------------------------
# IPTracker integration
# ---------------------------------------------------------------------------

class TestTrackerIntegration:
    def test_failures_are_recorded_to_tracker(self, make_auth):
        t = IPTracker(ttl_seconds=300)
        rule = SSHBruteForceRule(threshold=3, window_seconds=60, tracker=t)

        entry = make_auth(source_ip=ATTACKER, event_type="failed_password",
                          timestamp=BASE_TS)
        list(rule.feed(entry))

        ref = BASE_TS + timedelta(seconds=1)
        events = t.query(ATTACKER, protocol="ssh", event_type="failure", reference_ts=ref)
        assert len(events) == 1
        assert "admin" in events[0].detail

    def test_success_is_recorded_to_tracker(self, make_auth):
        t = IPTracker(ttl_seconds=300)
        rule = SSHBruteForceRule(threshold=3, window_seconds=60, tracker=t)

        # A failure must exist to avoid the empty-buffer early-return in _handle_success
        failure = make_auth(source_ip=ATTACKER, event_type="failed_password",
                            timestamp=BASE_TS)
        list(rule.feed(failure))

        success = make_auth(source_ip=ATTACKER, event_type="accepted_password",
                            timestamp=BASE_TS + timedelta(seconds=1))
        list(rule.feed(success))

        ref = BASE_TS + timedelta(seconds=2)
        events = t.query(ATTACKER, protocol="ssh", event_type="success", reference_ts=ref)
        assert len(events) == 1

    def test_rule_without_tracker_still_detects(self, make_auth):
        rule = SSHBruteForceRule(threshold=3, window_seconds=60, tracker=None)
        incidents = []
        for i in range(3):
            entry = make_auth(source_ip=ATTACKER, event_type="failed_password",
                              timestamp=BASE_TS + timedelta(seconds=i))
            incidents.extend(rule.feed(entry))

        assert any(inc.severity == Severity.HIGH for inc in incidents)


# ---------------------------------------------------------------------------
# Entry type gating
# ---------------------------------------------------------------------------

def test_web_entries_are_ignored_by_ssh_rule(make_web):
    rule = SSHBruteForceRule(threshold=3, window_seconds=60)
    incidents = list(rule.feed(make_web()))
    assert not incidents
