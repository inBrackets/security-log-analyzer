"""
Tests for SuspiciousSudoRule — sensitive-target matching, event-type gating,
stateless per-entry firing, and incident attributes.
"""
from __future__ import annotations

import pytest

from analyzer.models import Severity
from analyzer.rules.suspicious_sudo import SuspiciousSudoRule


# ---------------------------------------------------------------------------
# True positives — each sensitive target must trigger CRITICAL
# ---------------------------------------------------------------------------

class TestSensitiveTargets:
    @pytest.mark.parametrize("sudo_command", [
        "/bin/cat /etc/shadow",
        "/bin/cat /etc/passwd",
        "/usr/bin/cp /home/user/.ssh/id_rsa /tmp/key",
        "/bin/ls .ssh/authorized_keys",
        "/bin/cat /etc/sudoers",
        "cat /proc/1/cmdline",
        "/bin/dd if=/dev/mem of=/tmp/dump",
    ])
    def test_sensitive_command_fires_critical(self, sudo_command, make_auth):
        rule = SuspiciousSudoRule()
        entry = make_auth(
            event_type="sudo",
            sudo_command=sudo_command,
            target_user="root",
        )
        incidents = list(rule.feed(entry))
        assert len(incidents) == 1
        assert incidents[0].severity == Severity.CRITICAL

    def test_command_with_multiple_sensitive_targets_fires_once(self, make_auth):
        """A single entry matching two targets still yields exactly one incident."""
        rule = SuspiciousSudoRule()
        entry = make_auth(
            event_type="sudo",
            sudo_command="/bin/cat /etc/shadow /etc/passwd",
            target_user="root",
        )
        incidents = list(rule.feed(entry))
        assert len(incidents) == 1
        assert incidents[0].severity == Severity.CRITICAL

    def test_multiple_matched_targets_appear_in_evidence(self, make_auth):
        rule = SuspiciousSudoRule()
        entry = make_auth(
            event_type="sudo",
            sudo_command="/bin/cat /etc/shadow /etc/passwd",
            target_user="root",
        )
        inc = list(rule.feed(entry))[0]
        evidence_text = " ".join(inc.evidence)
        assert "/etc/shadow" in evidence_text
        assert "/etc/passwd" in evidence_text


# ---------------------------------------------------------------------------
# False positives — non-sensitive commands must not fire
# ---------------------------------------------------------------------------

class TestNonSensitiveCommands:
    @pytest.mark.parametrize("sudo_command", [
        "/usr/bin/apt-get install nginx",
        "/bin/systemctl restart nginx",
        "/usr/bin/journalctl -u ssh",
        "/bin/ls /var/log",
        "/usr/bin/whoami",
    ])
    def test_non_sensitive_command_does_not_fire(self, sudo_command, make_auth):
        rule = SuspiciousSudoRule()
        entry = make_auth(
            event_type="sudo",
            sudo_command=sudo_command,
            target_user="root",
        )
        assert not list(rule.feed(entry))


# ---------------------------------------------------------------------------
# Entry-type gating
# ---------------------------------------------------------------------------

class TestEntryGating:
    def test_non_sudo_auth_entry_is_ignored(self, make_auth):
        rule = SuspiciousSudoRule()
        for event_type in ("failed_password", "accepted_password", "connection_closed"):
            entry = make_auth(event_type=event_type,
                              sudo_command="/bin/cat /etc/shadow")
            assert not list(rule.feed(entry)), f"unexpected fire for {event_type}"

    def test_sudo_entry_with_no_command_is_ignored(self, make_auth):
        rule = SuspiciousSudoRule()
        entry = make_auth(event_type="sudo", sudo_command=None, target_user="root")
        assert not list(rule.feed(entry))

    def test_web_entries_are_ignored(self, make_web):
        rule = SuspiciousSudoRule()
        assert not list(rule.feed(make_web()))


# ---------------------------------------------------------------------------
# Stateless behaviour — fires on every matching entry
# ---------------------------------------------------------------------------

class TestStateless:
    def test_every_matching_entry_produces_an_incident(self, make_auth):
        """SuspiciousSudoRule has no _alerted guard — fires on each match."""
        rule = SuspiciousSudoRule()
        incidents = []
        for _ in range(3):
            entry = make_auth(event_type="sudo",
                              sudo_command="/bin/cat /etc/shadow",
                              target_user="root")
            incidents.extend(rule.feed(entry))
        assert len(incidents) == 3


# ---------------------------------------------------------------------------
# Incident attributes
# ---------------------------------------------------------------------------

class TestIncidentAttributes:
    def _fire(self, make_auth):
        rule = SuspiciousSudoRule()
        entry = make_auth(
            event_type="sudo",
            username="johndoe",
            sudo_command="/bin/cat /etc/shadow",
            target_user="root",
        )
        return list(rule.feed(entry))[0]

    def test_severity_is_critical(self, make_auth):
        assert self._fire(make_auth).severity == Severity.CRITICAL

    def test_rule_name(self, make_auth):
        assert self._fire(make_auth).rule_name == "suspicious_sudo"

    def test_source_ip_is_none(self, make_auth):
        """sudo is a local operation — no remote IP is available."""
        assert self._fire(make_auth).source_ip is None

    def test_description_mentions_username_command_and_target(self, make_auth):
        inc = self._fire(make_auth)
        assert "johndoe" in inc.description
        assert "/bin/cat /etc/shadow" in inc.description
        assert "root" in inc.description

    def test_evidence_contains_raw_line(self, make_auth):
        inc = self._fire(make_auth)
        assert inc.evidence[0] == "[test raw line]"

    def test_evidence_contains_matched_targets(self, make_auth):
        inc = self._fire(make_auth)
        assert any("Sensitive targets" in line for line in inc.evidence)
