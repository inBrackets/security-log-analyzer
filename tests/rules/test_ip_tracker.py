"""
Unit tests for IPTracker — storage, eviction, and query filtering.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from analyzer.rules.ip_tracker import IPEvent, IPTracker
from tests.conftest import BASE_TS


def _ev(*, protocol="ssh", event_type="failure", ts_offset: float = 0, detail="test") -> IPEvent:
    return IPEvent(
        timestamp=BASE_TS + timedelta(seconds=ts_offset),
        protocol=protocol,
        event_type=event_type,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# record / basic retrieval
# ---------------------------------------------------------------------------

_REF = BASE_TS + timedelta(seconds=10)  # reference timestamp close to all test events


class TestRecord:
    def test_stored_event_is_retrievable(self):
        t = IPTracker()
        t.record("1.2.3.4", _ev())
        assert len(t.query("1.2.3.4", reference_ts=_REF)) == 1

    def test_unknown_ip_returns_empty_list(self):
        # Pass reference_ts so the window filter doesn't exclude events by accident
        assert IPTracker().query("9.9.9.9", reference_ts=_REF) == []

    def test_multiple_events_accumulate_per_ip(self):
        t = IPTracker()
        for i in range(5):
            t.record("1.2.3.4", _ev(ts_offset=i))
        assert len(t.query("1.2.3.4", reference_ts=_REF)) == 5

    def test_events_for_different_ips_are_isolated(self):
        t = IPTracker()
        t.record("1.1.1.1", _ev(detail="A"))
        t.record("2.2.2.2", _ev(detail="B"))

        result_a = t.query("1.1.1.1", reference_ts=_REF)
        result_b = t.query("2.2.2.2", reference_ts=_REF)

        assert len(result_a) == 1 and result_a[0].detail == "A"
        assert len(result_b) == 1 and result_b[0].detail == "B"

    def test_events_are_ordered_by_insertion(self):
        t = IPTracker()
        for i in range(3):
            t.record("1.2.3.4", _ev(ts_offset=i, detail=str(i)))
        events = t.query("1.2.3.4", reference_ts=_REF)
        assert [e.detail for e in events] == ["0", "1", "2"]


# ---------------------------------------------------------------------------
# Lazy eviction
# ---------------------------------------------------------------------------

class TestEviction:
    def test_old_events_evicted_when_new_event_arrives(self):
        t = IPTracker(ttl_seconds=60)
        t.record("1.2.3.4", _ev(ts_offset=0))
        t.record("1.2.3.4", _ev(ts_offset=120))  # triggers eviction of offset=0

        ref = BASE_TS + timedelta(seconds=120)
        result = t.query("1.2.3.4", reference_ts=ref, window_seconds=60)
        assert len(result) == 1
        assert result[0].timestamp == BASE_TS + timedelta(seconds=120)

    def test_events_within_ttl_are_retained(self):
        t = IPTracker(ttl_seconds=300)
        for i in range(3):
            t.record("1.2.3.4", _ev(ts_offset=i * 10))

        ref = BASE_TS + timedelta(seconds=30)
        assert len(t.query("1.2.3.4", reference_ts=ref, window_seconds=300)) == 3

    def test_all_events_evicted_leaves_empty_result(self):
        t = IPTracker(ttl_seconds=60)
        t.record("1.2.3.4", _ev(ts_offset=0))
        t.record("1.2.3.4", _ev(ts_offset=1))
        t.record("1.2.3.4", _ev(ts_offset=200))  # evicts both previous

        ref = BASE_TS + timedelta(seconds=200)
        result = t.query("1.2.3.4", reference_ts=ref, window_seconds=60)
        assert len(result) == 1  # only the t=200 event remains within the 60s window


# ---------------------------------------------------------------------------
# query() filtering
# ---------------------------------------------------------------------------

class TestQuery:
    def test_filter_by_event_type(self):
        t = IPTracker()
        t.record("1.2.3.4", _ev(event_type="failure"))
        t.record("1.2.3.4", _ev(event_type="success"))

        failures = t.query("1.2.3.4", event_type="failure", reference_ts=_REF)
        successes = t.query("1.2.3.4", event_type="success", reference_ts=_REF)

        assert len(failures) == 1 and failures[0].event_type == "failure"
        assert len(successes) == 1 and successes[0].event_type == "success"

    def test_filter_by_protocol(self):
        t = IPTracker()
        t.record("1.2.3.4", _ev(protocol="ssh"))
        t.record("1.2.3.4", _ev(protocol="web"))

        ssh = t.query("1.2.3.4", protocol="ssh", reference_ts=_REF)
        web = t.query("1.2.3.4", protocol="web", reference_ts=_REF)

        assert len(ssh) == 1 and ssh[0].protocol == "ssh"
        assert len(web) == 1 and web[0].protocol == "web"

    def test_window_seconds_excludes_older_events(self):
        t = IPTracker(ttl_seconds=3600)
        ref = BASE_TS + timedelta(seconds=200)
        t.record("1.2.3.4", _ev(ts_offset=0))    # 200s before ref — outside 60s window
        t.record("1.2.3.4", _ev(ts_offset=150))  # 50s before ref — inside 60s window

        result = t.query("1.2.3.4", window_seconds=60, reference_ts=ref)

        assert len(result) == 1
        assert result[0].timestamp == BASE_TS + timedelta(seconds=150)

    def test_no_filters_returns_all_events_in_ttl(self):
        t = IPTracker(ttl_seconds=300)
        for i in range(4):
            t.record("1.2.3.4", _ev(protocol="ssh" if i % 2 == 0 else "web",
                                     event_type="failure" if i < 3 else "success",
                                     ts_offset=i))
        assert len(t.query("1.2.3.4", reference_ts=_REF)) == 4

    def test_combined_filters(self):
        t = IPTracker()
        t.record("1.2.3.4", _ev(protocol="ssh", event_type="failure"))
        t.record("1.2.3.4", _ev(protocol="ssh", event_type="success"))
        t.record("1.2.3.4", _ev(protocol="web", event_type="failure"))

        result = t.query("1.2.3.4", protocol="ssh", event_type="failure", reference_ts=_REF)

        assert len(result) == 1
        assert result[0].protocol == "ssh"
        assert result[0].event_type == "failure"


# ---------------------------------------------------------------------------
# active_failure_protocols()
# ---------------------------------------------------------------------------

class TestActiveFailureProtocols:
    def test_returns_protocols_with_at_least_one_failure(self):
        t = IPTracker()
        t.record("1.2.3.4", _ev(protocol="ssh", event_type="failure"))
        t.record("1.2.3.4", _ev(protocol="web", event_type="failure"))

        ref = BASE_TS + timedelta(seconds=1)
        protocols = t.active_failure_protocols("1.2.3.4", 300, ref)

        assert protocols == {"ssh", "web"}

    def test_ignores_success_events(self):
        t = IPTracker()
        t.record("1.2.3.4", _ev(protocol="ssh", event_type="success"))

        ref = BASE_TS + timedelta(seconds=1)
        protocols = t.active_failure_protocols("1.2.3.4", 300, ref)

        assert protocols == set()

    def test_returns_empty_for_unknown_ip(self):
        t = IPTracker()
        protocols = t.active_failure_protocols("9.9.9.9", 60, BASE_TS)
        assert protocols == set()

    def test_excludes_protocols_outside_window(self):
        t = IPTracker(ttl_seconds=3600)
        t.record("1.2.3.4", _ev(protocol="ssh", event_type="failure", ts_offset=0))
        t.record("1.2.3.4", _ev(protocol="web", event_type="failure", ts_offset=200))

        ref = BASE_TS + timedelta(seconds=200)
        protocols = t.active_failure_protocols("1.2.3.4", window_seconds=60, reference_ts=ref)

        assert protocols == {"web"}  # ssh event is 200s old — outside 60s window
