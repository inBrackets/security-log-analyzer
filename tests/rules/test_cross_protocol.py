"""
Tests for CrossProtocolBruteForceRule — cross-log correlation using IPTracker.

The rule reads from a shared IPTracker populated by SSHBruteForceRule and
WebBruteForceRule.  In unit tests the tracker is populated directly with
IPEvent objects to isolate the rule's own logic.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from analyzer.models import Severity
from analyzer.rules.cross_protocol import CrossProtocolBruteForceRule
from analyzer.rules.ip_tracker import IPEvent, IPTracker
from tests.conftest import BASE_TS
ATTACKER = "10.0.0.50"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ev(protocol: str, event_type: str = "failure", ts_offset: float = 0) -> IPEvent:
    return IPEvent(
        timestamp=BASE_TS + timedelta(seconds=ts_offset),
        protocol=protocol,
        event_type=event_type,
        detail=f"{protocol} {event_type}",
    )


def _tracker_with(
    ssh_failures: int = 0,
    web_failures: int = 0,
    ts_start: float = 0,
) -> IPTracker:
    t = IPTracker(ttl_seconds=300)
    for i in range(ssh_failures):
        t.record(ATTACKER, _ev("ssh", ts_offset=ts_start + i))
    for i in range(web_failures):
        t.record(ATTACKER, _ev("web", ts_offset=ts_start + i))
    return t


# ---------------------------------------------------------------------------
# Happy-path: rule fires when both protocols meet the threshold
# ---------------------------------------------------------------------------

class TestFiringConditions:
    def test_fires_when_both_protocols_meet_threshold(self, make_web):
        tracker = _tracker_with(ssh_failures=2, web_failures=2)
        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2, window_seconds=120)

        entry = make_web(
            source_ip=ATTACKER, status_code=401, path="/login",
            timestamp=BASE_TS + timedelta(seconds=5),
        )
        incidents = list(rule.feed(entry))

        assert len(incidents) == 1
        assert incidents[0].severity == Severity.CRITICAL

    def test_incident_description_names_both_protocols(self, make_web):
        tracker = _tracker_with(ssh_failures=2, web_failures=2)
        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2, window_seconds=300)

        entry = make_web(source_ip=ATTACKER, status_code=401, path="/login",
                         timestamp=BASE_TS + timedelta(seconds=5))
        incidents = list(rule.feed(entry))

        desc = incidents[0].description
        assert "SSH" in desc
        assert "WEB" in desc

    def test_incident_evidence_contains_both_protocols(self, make_web):
        tracker = _tracker_with(ssh_failures=2, web_failures=2)
        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2, window_seconds=300)

        entry = make_web(source_ip=ATTACKER, status_code=401, path="/login",
                         timestamp=BASE_TS + timedelta(seconds=5))
        incidents = list(rule.feed(entry))

        evidence = " ".join(incidents[0].evidence)
        assert "[SSH]" in evidence
        assert "[WEB]" in evidence

    def test_incident_source_ip_matches_attacker(self, make_web):
        tracker = _tracker_with(ssh_failures=2, web_failures=2)
        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2, window_seconds=300)

        entry = make_web(source_ip=ATTACKER, status_code=401, path="/login",
                         timestamp=BASE_TS + timedelta(seconds=5))
        incidents = list(rule.feed(entry))

        assert incidents[0].source_ip == ATTACKER
        assert incidents[0].rule_name == "cross_protocol_brute_force"


# ---------------------------------------------------------------------------
# Threshold enforcement
# ---------------------------------------------------------------------------

class TestThresholdEnforcement:
    @pytest.mark.parametrize("ssh_count,web_count,threshold,expect_fire", [
        (2, 2, 2, True),   # both exactly at threshold
        (3, 3, 2, True),   # both above threshold
        (1, 2, 2, False),  # SSH below threshold
        (2, 1, 2, False),  # web below threshold
        (2, 2, 3, False),  # both at 2 but threshold is 3
        (0, 5, 2, False),  # SSH has no failures at all
        (5, 0, 2, False),  # web has no failures at all
    ])
    def test_per_protocol_threshold(self, ssh_count, web_count, threshold, expect_fire, make_web):
        tracker = _tracker_with(ssh_failures=ssh_count, web_failures=web_count)
        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=threshold,
                                           window_seconds=300)

        entry = make_web(source_ip=ATTACKER, status_code=401, path="/login",
                         timestamp=BASE_TS + timedelta(seconds=10))
        incidents = list(rule.feed(entry))

        assert bool(incidents) == expect_fire, (
            f"ssh={ssh_count} web={web_count} threshold={threshold}: "
            f"expected_fire={expect_fire}, got={bool(incidents)}"
        )


# ---------------------------------------------------------------------------
# Single-protocol scenarios must not fire
# ---------------------------------------------------------------------------

class TestSingleProtocol:
    def test_no_fire_with_only_ssh_failures(self, make_auth):
        tracker = _tracker_with(ssh_failures=5, web_failures=0)
        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2)

        entry = make_auth(source_ip=ATTACKER, event_type="failed_password",
                          timestamp=BASE_TS + timedelta(seconds=5))
        incidents = list(rule.feed(entry))

        assert not incidents

    def test_no_fire_with_only_web_failures(self, make_web):
        tracker = _tracker_with(ssh_failures=0, web_failures=5)
        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2)

        entry = make_web(source_ip=ATTACKER, status_code=401, path="/login",
                         timestamp=BASE_TS + timedelta(seconds=5))
        incidents = list(rule.feed(entry))

        assert not incidents


# ---------------------------------------------------------------------------
# Deduplication — fires at most once per IP per session
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_fires_only_once_per_ip(self, make_web):
        tracker = _tracker_with(ssh_failures=3, web_failures=3)
        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2, window_seconds=300)

        incidents = []
        for i in range(5):
            tracker.record(ATTACKER, _ev("web", ts_offset=10 + i))
            entry = make_web(source_ip=ATTACKER, status_code=401, path="/login",
                             timestamp=BASE_TS + timedelta(seconds=10 + i))
            incidents.extend(rule.feed(entry))

        criticals = [inc for inc in incidents if inc.severity == Severity.CRITICAL]
        assert len(criticals) == 1

    def test_second_ip_fires_independently(self, make_web):
        """Deduplication is per-IP; a different IP still triggers a separate incident."""
        tracker = IPTracker(ttl_seconds=300)
        second_ip = "198.51.100.7"

        for ip in [ATTACKER, second_ip]:
            for i in range(2):
                tracker.record(ip, _ev("ssh", ts_offset=i))
                tracker.record(ip, _ev("web", ts_offset=i))

        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2, window_seconds=300)

        incidents = []
        for ip in [ATTACKER, second_ip]:
            entry = make_web(source_ip=ip, status_code=401, path="/login",
                             timestamp=BASE_TS + timedelta(seconds=5))
            incidents.extend(rule.feed(entry))

        fired_ips = {inc.source_ip for inc in incidents}
        assert fired_ips == {ATTACKER, second_ip}


# ---------------------------------------------------------------------------
# Entry type gating — only failure entries trigger the check
# ---------------------------------------------------------------------------

class TestEntryGating:
    def test_success_entries_do_not_trigger_check(self, make_web):
        tracker = _tracker_with(ssh_failures=5, web_failures=5)
        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2)

        success = make_web(source_ip=ATTACKER, status_code=200, path="/login",
                           timestamp=BASE_TS + timedelta(seconds=5))
        incidents = list(rule.feed(success))

        assert not incidents  # status 200 is not a failure — check is not triggered

    def test_auth_success_does_not_trigger_check(self, make_auth):
        tracker = _tracker_with(ssh_failures=5, web_failures=5)
        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2)

        success = make_auth(source_ip=ATTACKER, event_type="accepted_password",
                            timestamp=BASE_TS + timedelta(seconds=5))
        incidents = list(rule.feed(success))

        assert not incidents  # accepted_password is not a failure

    def test_different_ip_in_tracker_does_not_trigger(self, make_web):
        """Events for one IP don't fire for a different attacking IP."""
        tracker = IPTracker(ttl_seconds=300)
        for i in range(3):
            tracker.record("1.1.1.1", _ev("ssh", ts_offset=i))
            tracker.record("1.1.1.1", _ev("web", ts_offset=i))

        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2)

        # Feed failure from a COMPLETELY DIFFERENT IP
        entry = make_web(source_ip="2.2.2.2", status_code=401, path="/login",
                         timestamp=BASE_TS + timedelta(seconds=5))
        incidents = list(rule.feed(entry))

        assert not incidents


# ---------------------------------------------------------------------------
# Time-window filtering
# ---------------------------------------------------------------------------

class TestTimeWindow:
    def test_stale_failures_outside_window_not_counted(self, make_web):
        tracker = IPTracker(ttl_seconds=3600)

        # Populate with events that are 200s old
        for i in range(3):
            tracker.record(ATTACKER, _ev("ssh", ts_offset=i))
            tracker.record(ATTACKER, _ev("web", ts_offset=i))

        rule = CrossProtocolBruteForceRule(tracker, threshold_per_protocol=2, window_seconds=60)

        # Current time is 200s later — all tracker events are outside the 60s window
        entry = make_web(source_ip=ATTACKER, status_code=401, path="/login",
                         timestamp=BASE_TS + timedelta(seconds=200))
        incidents = list(rule.feed(entry))

        assert not incidents
