from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(Enum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class LogEntry:
    raw: str
    timestamp: Optional[datetime]
    source_ip: Optional[str]


@dataclass
class AuthEntry(LogEntry):
    hostname: str = ""
    process: str = ""
    pid: Optional[int] = None
    event_type: str = ""          # failed_password | accepted_password | connection_closed | sudo
    username: Optional[str] = None
    target_user: Optional[str] = None  # sudo: target USER=
    port: Optional[int] = None
    protocol: Optional[str] = None
    is_invalid_user: bool = False
    sudo_command: Optional[str] = None
    sudo_cwd: Optional[str] = None


@dataclass
class WebEntry(LogEntry):
    method: str = ""
    path: str = ""
    query: str = ""
    http_version: str = ""
    status_code: int = 0
    response_size: int = 0


@dataclass
class Incident:
    rule_name: str
    severity: Severity
    source_ip: Optional[str]
    description: str
    evidence: list[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    count: int = 1
