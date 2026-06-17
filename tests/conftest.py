from __future__ import annotations

import pytest
from datetime import datetime, timedelta

from analyzer.models import AuthEntry, WebEntry
from analyzer.rules.ip_tracker import IPEvent, IPTracker

# Anchor timestamp shared across all test modules
BASE_TS = datetime(2025, 7, 3, 10, 0, 0)


# ---------------------------------------------------------------------------
# Entry factories — exposed as fixtures that return the factory callable so
# parametrized test functions can request them by name and call with kwargs.
# ---------------------------------------------------------------------------

@pytest.fixture
def make_auth():
    def _factory(
        *,
        event_type: str = "failed_password",
        username: str = "admin",
        source_ip: str = "192.0.2.1",
        port: int = 22222,
        timestamp: datetime | None = None,
        is_invalid_user: bool = False,
        target_user: str | None = None,
        sudo_command: str | None = None,
        sudo_cwd: str | None = None,
        protocol: str = "ssh2",
        process: str = "sshd",
    ) -> AuthEntry:
        return AuthEntry(
            raw="[test raw line]",
            timestamp=timestamp or BASE_TS,
            source_ip=source_ip,
            hostname="testhost",
            process=process,
            pid=9999,
            event_type=event_type,
            username=username,
            port=port,
            protocol=protocol,
            is_invalid_user=is_invalid_user,
            target_user=target_user,
            sudo_command=sudo_command,
            sudo_cwd=sudo_cwd,
        )

    return _factory


@pytest.fixture
def make_web():
    def _factory(
        *,
        method: str = "GET",
        path: str = "/search",
        query: str = "",
        status_code: int = 200,
        source_ip: str = "192.0.2.1",
        timestamp: datetime | None = None,
        response_size: int = 1234,
    ) -> WebEntry:
        return WebEntry(
            raw="[test raw line]",
            timestamp=timestamp or BASE_TS,
            source_ip=source_ip,
            method=method,
            path=path,
            query=query,
            status_code=status_code,
            response_size=response_size,
            http_version="1.1",
        )

    return _factory


@pytest.fixture
def tracker() -> IPTracker:
    return IPTracker(ttl_seconds=300)
