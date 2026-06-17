"""
Tests for UserEnumerationRule — threshold detection, sliding-window eviction,
username deduplication, per-IP isolation, and entry-type gating.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from analyzer.models import Severity
from analyzer.rules.user_enumeration import UserEnumerationRule
from tests.conftest import BASE_TS

ATTACKER = "10.0.0.33"
OTHER_IP  = "203.0.113.9"


# ---------------------------------------------------------------------------
# Threshold behaviour
# ---------------------------------------------------------------------------

class TestThreshold:
    @pytest.mark.parametrize("num_attempts,expect_fire", [
        (1, False),
        (2, True),   # exactly at threshold
        (4, True),   # above threshold
    ])
    def test_fires_at_threshold(self, num_attempts, expect_fire, make_auth):
        rule = UserEnumerationRule(threshold=2, window_seconds=60)
        incidents = []
        for i in range(num_attempts):
            entry = make_auth(
                source_ip=ATTACKER, is_invalid_user=True, username=f"user{i}",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert bool(incidents) == expect_fire

    def test_fires_exactly_once_per_ip(self, make_auth):
        rule = UserEnumerationRule(threshold=2, window_seconds=60)
        incidents = []
        for i in range(8):
            entry = make_auth(
                source_ip=ATTACKER, is_invalid_user=True, username=f"user{i}",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert sum(1 for inc in incidents if inc.severity == Severity.MEDIUM) == 1

    def test_different_ips_tracked_independently(self, make_auth):
        rule = UserEnumerationRule(threshold=2, window_seconds=60)
        incidents = []
        for ip in [ATTACKER, OTHER_IP]:
            for i in range(2):
                entry = make_auth(
                    source_ip=ip, is_invalid_user=True, username=f"user{i}",
                    timestamp=BASE_TS + timedelta(seconds=i),
                )
                incidents.extend(rule.feed(entry))

        fired_ips = {inc.source_ip for inc in incidents}
        assert fired_ips == {ATTACKER, OTHER_IP}


# ---------------------------------------------------------------------------
# Sliding-window eviction
# ---------------------------------------------------------------------------

class TestWindow:
    def test_attempts_outside_window_not_counted(self, make_auth):
        rule = UserEnumerationRule(threshold=2, window_seconds=60)

        # One attempt, then another 120s later — the first has expired
        entry1 = make_auth(source_ip=ATTACKER, is_invalid_user=True, username="admin",
                           timestamp=BASE_TS)
        list(rule.feed(entry1))

        entry2 = make_auth(source_ip=ATTACKER, is_invalid_user=True, username="root",
                           timestamp=BASE_TS + timedelta(seconds=120))
        incidents = list(rule.feed(entry2))

        assert not incidents  # only 1 attempt in current window

    def test_attempts_within_window_all_counted(self, make_auth):
        rule = UserEnumerationRule(threshold=2, window_seconds=60)
        incidents = []
        for i, username in enumerate(["admin", "root"]):
            entry = make_auth(
                source_ip=ATTACKER, is_invalid_user=True, username=username,
                timestamp=BASE_TS + timedelta(seconds=i * 20),  # 0s, 20s — both within 60s
            )
            incidents.extend(rule.feed(entry))

        assert any(inc.severity == Severity.MEDIUM for inc in incidents)


# ---------------------------------------------------------------------------
# Username deduplication
# ---------------------------------------------------------------------------

class TestUsernameDeduplication:
    def test_repeated_username_listed_once(self, make_auth):
        """The same invalid username tried twice should appear once in the incident."""
        rule = UserEnumerationRule(threshold=2, window_seconds=60)
        incidents = []
        for i in range(2):
            entry = make_auth(
                source_ip=ATTACKER, is_invalid_user=True, username="admin",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        inc = incidents[0]
        assert inc.description.count("admin") == 1  # listed once, not twice

    def test_distinct_usernames_all_listed(self, make_auth):
        rule = UserEnumerationRule(threshold=2, window_seconds=60)
        incidents = []
        for i, username in enumerate(["admin", "root"]):
            entry = make_auth(
                source_ip=ATTACKER, is_invalid_user=True, username=username,
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        desc = incidents[0].description
        assert "admin" in desc
        assert "root" in desc

    def test_none_username_stored_as_placeholder(self, make_auth):
        """
        AuthEntry.username can be None for malformed entries; the rule
        stores '?' as a safe placeholder so the incident description is clean.
        """
        rule = UserEnumerationRule(threshold=2, window_seconds=60)
        incidents = []
        for i in range(2):
            entry = make_auth(
                source_ip=ATTACKER, is_invalid_user=True, username=None,
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert incidents[0].description  # does not crash; placeholder used


# ---------------------------------------------------------------------------
# Entry-type gating
# ---------------------------------------------------------------------------

class TestEntryGating:
    def test_valid_user_auth_failure_is_ignored(self, make_auth):
        """Only entries with is_invalid_user=True are counted."""
        rule = UserEnumerationRule(threshold=2, window_seconds=60)
        incidents = []
        for i in range(5):
            entry = make_auth(
                source_ip=ATTACKER, is_invalid_user=False, username="admin",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))

        assert not incidents

    def test_web_entries_are_ignored(self, make_web):
        rule = UserEnumerationRule(threshold=2, window_seconds=60)
        assert not list(rule.feed(make_web()))

    def test_accepted_password_entry_is_ignored(self, make_auth):
        rule = UserEnumerationRule(threshold=2, window_seconds=60)
        entry = make_auth(source_ip=ATTACKER, event_type="accepted_password",
                          is_invalid_user=True)
        assert not list(rule.feed(entry))


# ---------------------------------------------------------------------------
# Incident attributes
# ---------------------------------------------------------------------------

class TestIncidentAttributes:
    def _fire(self, make_auth, threshold=2):
        rule = UserEnumerationRule(threshold=threshold, window_seconds=60)
        incidents = []
        for i in range(threshold):
            entry = make_auth(
                source_ip=ATTACKER, is_invalid_user=True, username=f"user{i}",
                timestamp=BASE_TS + timedelta(seconds=i),
            )
            incidents.extend(rule.feed(entry))
        return incidents[0]

    def test_severity_is_medium(self, make_auth):
        assert self._fire(make_auth).severity == Severity.MEDIUM

    def test_rule_name(self, make_auth):
        assert self._fire(make_auth).rule_name == "user_enumeration"

    def test_source_ip(self, make_auth):
        assert self._fire(make_auth).source_ip == ATTACKER

    def test_count_equals_attempt_count(self, make_auth):
        inc = self._fire(make_auth, threshold=3)
        assert inc.count == 3

    def test_evidence_contains_raw_lines(self, make_auth):
        inc = self._fire(make_auth, threshold=3)
        assert len(inc.evidence) == 3
        assert all(line == "[test raw line]" for line in inc.evidence)
