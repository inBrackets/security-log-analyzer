from .base import BaseRule
from .cross_protocol import CrossProtocolBruteForceRule
from .ip_tracker import IPTracker
from .path_traversal import PathTraversalRule
from .sql_injection import SQLInjectionRule
from .ssh_brute_force import SSHBruteForceRule
from .suspicious_sudo import SuspiciousSudoRule
from .user_enumeration import UserEnumerationRule
from .web_brute_force import WebBruteForceRule


def build_rules() -> list[BaseRule]:
    """
    Construct and return a fully-wired rule set.

    A single IPTracker is created here and injected into every rule that
    participates in cross-protocol correlation.  Rules that don't need shared
    state (SQLInjectionRule, PathTraversalRule, …) are instantiated normally.

    To add a new rule
    -----------------
    1. Create `analyzer/rules/my_rule.py` with a class that extends BaseRule.
    2. Import it here.
    3. Instantiate it in the list below (inject the tracker if needed).
    Nothing else changes.
    """
    tracker = IPTracker(ttl_seconds=300)

    return [
        SSHBruteForceRule(tracker=tracker),
        WebBruteForceRule(tracker=tracker),
        CrossProtocolBruteForceRule(tracker=tracker),
        SQLInjectionRule(),
        PathTraversalRule(),
        SuspiciousSudoRule(),
        UserEnumerationRule(),
    ]
