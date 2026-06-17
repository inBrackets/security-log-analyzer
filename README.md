# Security Log Analyzer

A streaming Python CLI tool that detects security incidents in Linux auth logs and web server access logs. Designed around the **Open/Closed Principle** (SOLID), it processes arbitrarily large files in constant memory by reading line-by-line through generators, with zero external runtime dependencies.

---

## Features

| Detection Rule | Triggers on | Severity |
|---|---|---|
| `ssh_brute_force` | Repeated SSH password failures from a single IP | HIGH -> CRITICAL on success |
| `web_brute_force` | Repeated HTTP 401s on login endpoints | HIGH -> CRITICAL on POST 200 |
| `cross_protocol_brute_force` | Same IP attacking both SSH and HTTP simultaneously | CRITICAL |
| `sql_injection` | SQL structural patterns in URL query strings | HIGH / CRITICAL |
| `path_traversal` | `../` sequences in request paths | HIGH / CRITICAL |
| `suspicious_sudo` | `sudo` commands accessing credential files | CRITICAL |
| `user_enumeration` | SSH "invalid user" probing bursts | MEDIUM |
| `web_scanner` | Single IP probing N+ distinct paths with 403/404 (recon sweep) | HIGH |
| `rapid_request` | Burst of identical POSTs to the same endpoint within a tight window | HIGH |

---

## Prerequisites

- Python 3.14+
- No third-party runtime dependencies (stdlib only)
- `pytest` for the test suite (dev only)

---

## Setup

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS

# 2. Install test dependencies
python -m pip install pytest
```

The project uses no `pip install` step for the tool itself -- all imports are from the standard library.

---

## Running the Tool

Running without arguments launches an **interactive menu** that walks you through log directory, output format, severity filter, and evidence display:

```bash
python main.py
```

To run non-interactively, pass flags directly:

```bash
# Human-readable narrative report (attack story grouped by attacker IP)
python main.py --output narrative

# Flat table filtered to HIGH and above, with supporting log lines
python main.py --min-severity HIGH --show-evidence

# Structured JSON for piping into a SIEM or jq
python main.py --output json --min-severity LOW

# Point at non-default log files
python main.py --auth-log /var/log/auth.log --web-log /var/log/nginx/access.log

# Capture parse warnings to a dedicated file (useful in CI/CD pipelines)
python main.py --parse-log parse-errors.log --verbose
```

### Example output (narrative mode)

```
======================================================================
  10.0.0.50  |  CRITICAL  |  COORDINATED MULTI-VECTOR ATTACK
======================================================================

  10:00:03  [CRITICAL ]  cross_protocol_brute_force
    Multi-vector brute force: 10.0.0.50 attacking via SSH + WEB simultaneously
    6 events over 3s

  10:00:06  [CRITICAL ]  sql_injection
    SQL injection on '/search' - server returned 200, payload may have reached the DB

----------------------------------------------------------------------
  (server-local)  |  CRITICAL  |  PRIVILEGE ESCALATION
----------------------------------------------------------------------

  10:00:15  [CRITICAL ]  suspicious_sudo
    Suspicious sudo: 'johndoe' ran '/bin/cat /etc/shadow' as 'root'
```

Incidents are grouped by attacker IP, sorted chronologically within each group, and the group header is labelled with a threat category (`COORDINATED MULTI-VECTOR ATTACK`, `PRIVILEGE ESCALATION`, `EXPLOITATION ATTEMPT`, etc.). CRITICAL groups use a `=` border; lower-severity groups use `-`.

### Example output (table mode)

```
SEVERITY  RULE                   SOURCE IP         DESCRIPTION                                             #   FIRST SEEN
--------- ---------------------- ----------------- ------------------------------------------------------- --- -------------------
CRITICAL  cross_protocol_b...    10.0.0.50         Multi-vector brute force: 10.0.0.50 attacking via      6   2025-07-03 10:00:03
                                                   SSH + WEB simultaneously
CRITICAL  sql_injection          10.0.0.50         SQL injection on '/search' - server returned 200,      1   2025-07-03 10:00:06
                                                   payload may have reached the DB
CRITICAL  suspicious_sudo        N/A               Suspicious sudo: 'johndoe' ran '/bin/cat /etc/shadow'  1   2025-07-03 10:00:15
                                                   as 'root'
```

### CLI reference

| Flag | Default | Description |
|---|---|---|
| `--log-dir PATH` | `logs/` | Directory containing `auth.log` and `webserver.log` |
| `--auth-log PATH` | (none) | Override path to auth log |
| `--web-log PATH` | (none) | Override path to web server log |
| `--output` | `table` | `table`, `json`, or `narrative` |
| `--min-severity` | `MEDIUM` | `INFO` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `--show-evidence` | off | Print the raw log lines that triggered each incident (table mode only) |
| `--verbose`, `-v` | off | Show parse warnings on stderr |
| `--parse-log FILE` | (none) | Write parse warnings to a file |

---

## Running the Tests

```bash
# Full suite with verbose output (configured in pyproject.toml)
python -m pytest

# Run a specific module
python -m pytest tests/rules/test_sql_injection.py -v

# Run only false-positive tests (O'Brien, etc.)
python -m pytest tests/rules/test_sql_injection.py -k "false_positive"
```

The suite contains **267 tests** across 12 files, all passing in under 2 seconds.

```
tests/parsers/test_auth_parser.py       13 tests
tests/parsers/test_web_parser.py        12 tests
tests/rules/test_ip_tracker.py          18 tests
tests/rules/test_sql_injection.py       36 tests
tests/rules/test_ssh_brute_force.py     17 tests
tests/rules/test_web_brute_force.py     17 tests
tests/rules/test_cross_protocol.py      29 tests
tests/rules/test_path_traversal.py      28 tests
tests/rules/test_suspicious_sudo.py     24 tests
tests/rules/test_user_enumeration.py    18 tests
tests/rules/test_web_scanner.py         25 tests
tests/rules/test_rapid_request.py       30 tests
```

---

## Architecture

### Directory structure

```
security-log-analyzer/
+-- main.py                        Entry point
+-- analyzer/
|   +-- models.py                  LogEntry, AuthEntry, WebEntry, Incident, Severity
|   +-- engine.py                  AnalysisEngine - wires parsers to rules
|   +-- cli.py                     Argument parsing, logging config, output dispatch
|   +-- output.py                  Table, JSON, and narrative formatters
|   +-- parsers/
|   |   +-- base.py                BaseParser ABC
|   |   +-- auth_parser.py         Syslog parser (auth.log)
|   |   +-- web_parser.py          Apache CLF parser (webserver.log)
|   +-- rules/
|       +-- base.py                BaseRule ABC
|       +-- ip_tracker.py          Shared, time-bounded per-IP event store
|       +-- sql_injection.py
|       +-- ssh_brute_force.py
|       +-- web_brute_force.py
|       +-- cross_protocol.py
|       +-- path_traversal.py
|       +-- suspicious_sudo.py
|       +-- user_enumeration.py
|       +-- web_scanner.py
|       +-- rapid_request.py
|       +-- __init__.py            build_rules() factory
+-- tests/
    +-- conftest.py                Shared fixtures and entry factories
    +-- parsers/
    +-- rules/
```

### Design decisions and their rationale

#### 1. Open/Closed Principle for detection rules

The engine and parsers are closed for modification. Adding a new detection capability requires exactly two steps:

1. Create `analyzer/rules/my_rule.py` with a class that extends `BaseRule`
2. Instantiate it in `build_rules()` in `rules/__init__.py`

Nothing else changes. This is enforced by the `BaseRule` abstract base class, which mandates `name`, `feed()`, and an optional `flush()` for rules that need to emit incidents at end-of-stream.

```python
class BaseRule(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def feed(self, entry: LogEntry) -> Iterator[Incident]: ...

    def flush(self) -> Iterator[Incident]:
        return iter([])
```

#### 2. Streaming generators for constant memory

The parsers are generators that yield one `LogEntry` at a time. The engine feeds one entry at a time into each rule. No file is ever loaded into memory in full. Peak memory is bounded to:

```
O(unique_active_IPs * events_within_TTL_window)
```

This makes the tool safe for production log files of any size (gigabytes or more). The output list in `cli.py` is the only place incidents are materialised -- a future streaming output mode (e.g., writing to a SIEM as incidents are detected) would eliminate even that.

#### 3. Shared state via dependency injection, not globals

Cross-protocol correlation (detecting the same IP attacking SSH and HTTP simultaneously) requires `SSHBruteForceRule`, `WebBruteForceRule`, and `CrossProtocolBruteForceRule` to share a common event store. Rather than a global singleton, a single `IPTracker` instance is constructed in `build_rules()` and injected into all three rules by constructor:

```python
def build_rules() -> list[BaseRule]:
    tracker = IPTracker(ttl_seconds=300)
    return [
        SSHBruteForceRule(tracker=tracker),
        WebBruteForceRule(tracker=tracker),
        CrossProtocolBruteForceRule(tracker=tracker),
        ...
    ]
```

The tracker is invisible to the engine -- it does not know about it. Rules that need correlation opt in at construction time; stateless rules (SQL injection, path traversal) ignore it entirely. This keeps the architecture testable: any rule can be instantiated in isolation with a fresh tracker or `None`.

#### 4. Lazy eviction in IPTracker -- no background thread

The `IPTracker` keeps a per-IP `deque` of timed events. Stale events are evicted not by a timer thread but lazily, the next time a new event arrives for that IP:

```python
def record(self, ip: str, event: IPEvent) -> None:
    buf = self._store[ip]
    buf.append(event)
    self._evict(buf, event.timestamp)   # evicts stale events right here
```

This keeps the data structure bounded without any concurrency or scheduler dependency. It is safe because the entire tool is single-threaded.

#### 5. Weighted signal scoring for SQL injection

A naive keyword match (flag any request containing `'` or `SELECT`) would generate enormous numbers of false positives -- apostrophes in surnames, product names, and prose text are common. Instead, the rule uses a weighted signal model. Each pattern targets unambiguous SQL *structure*, not individual tokens:

| Signal | Example match | Score |
|---|---|---|
| `UNION SELECT` | `' UNION SELECT * FROM users` | 10 |
| `DROP TABLE` | `1; DROP TABLE users` | 10 |
| `EXEC/EXECUTE` | `exec(xp_cmdshell('ls'))` | 8 |
| `INFORMATION_SCHEMA` | `information_schema.tables` | 8 |
| Stacked query (`;` + DML keyword) | `1; INSERT INTO ...` | 8 |
| String terminator + comment | `admin'--` | 7 |
| Boolean tautology | `OR 1=1` | 6 |
| Quote + comparison operator | `' OR '1'='1` | 5 |
| SQL line comment | `--` at end | 4 |
| SQL block comment | `/* ... */` | 4 |

**Threshold: 6 points.** A bare apostrophe (as in `O'Brien`) scores 0 and never fires. SQL structural combinations accumulate score rapidly: `' UNION SELECT * FROM users--` scores 21 points across three signals.

#### 6. Narrative output with threat labelling

The `narrative` output mode groups incidents by attacker IP and renders a human-readable attack story rather than a flat table. Each IP block is sorted chronologically, headed by a severity bar (`=` for CRITICAL, `-` for lower), and labelled with a threat category derived from the rule set that fired:

| Rules present | Label |
|---|---|
| `cross_protocol_brute_force` | COORDINATED MULTI-VECTOR ATTACK |
| `suspicious_sudo` | PRIVILEGE ESCALATION |
| `sql_injection` at CRITICAL | POSSIBLE DATA EXFILTRATION |
| `sql_injection` or `path_traversal` | EXPLOITATION ATTEMPT |
| `ssh_brute_force` / `web_brute_force` | CREDENTIAL ATTACK / BREACH |
| `user_enumeration` | RECONNAISSANCE |
| anything else | ACTIVE THREAT / SUSPICIOUS ACTIVITY |

This labelling is intentionally coarse-grained: the goal is a one-line context for a human analyst to prioritise triage, not a replacement for the raw incident data.

#### 7. Production-grade error handling in parsers

Log files in production environments contain binary garbage, truncated entries, and encoding anomalies. The parsers handle all of these defensively:

- **Encoding**: files are opened with `errors="replace"` -- a corrupted byte becomes `U+FFFD` rather than raising `UnicodeDecodeError` on an entire file.
- **Unrecognised lines**: lines that do not match the expected format (e.g., `[MALFORMED ENTRY - system restart`) are logged at `WARNING` level with the filename and 1-based line number, then skipped. Processing continues.
- **Unexpected exceptions**: any other exception inside `_parse_line()` (e.g., `int()` on a malformed port number that slipped through the regex) is caught, logged at `ERROR` with full traceback, and skipped. The stream never crashes.
- **Blank lines**: silently ignored without a log entry.

This hierarchy means operators can distinguish between "the file has noise" (WARNING) and "there is a bug in the parser" (ERROR) from a single log stream.

---

## QA Approach

### Test philosophy

The test suite treats the *contract* of each component as the subject under test -- not its implementation. Rules are tested by feeding them crafted `LogEntry` objects and asserting on the incidents they emit. Parsers are tested by writing actual log lines to temporary files and asserting on the parsed fields. No mocking of internal methods; no patching of regex patterns.

### Parser tests: correctness and resilience

**Happy paths** are parametrized across all syslog and CLF line variants, including edge cases present in the actual sample logs:

- The double-space padding used by syslog for single-digit days (`Jul  3` vs `Jul 3`) -- this caused a `strptime` failure that was fixed by normalising whitespace before parsing.
- URLs containing literal spaces (SQL injection payloads) -- this required switching the path capture group from `\S+` to a non-greedy `.*?` pattern.
- Timezone-aware CLF timestamps -- these must be stripped to naive `datetime` objects so they can be compared directly with timezone-naive syslog timestamps.

**Resilience** is tested with the `caplog` fixture, which intercepts log records without adding log handlers. Each malformed-line test asserts three things independently:

1. The number of entries yielded (malformed line is skipped)
2. That a `WARNING`-level record was emitted (the problem is visible to operators)
3. That the warning includes the correct filename and 1-based line number (operators can find the offending line)

### Detection rule tests: state machine coverage

Brute force rules are finite state machines: accumulate failures -> fire HIGH -> fire CRITICAL on success -> reset. The test suite covers every transition:

| State | Test |
|---|---|
| Below threshold -> no incident | `test_high_fires_at_threshold[1-False]`, `[2-False]` |
| At threshold -> HIGH fires once | `test_high_fires_at_threshold[3-True]`, `test_high_fires_exactly_once_per_ip` |
| Failures expire from window -> no incident | `test_failures_older_than_window_are_not_counted` |
| Success with no prior failures -> silent | `test_success_with_no_prior_failures_is_silent` |
| Success after failures -> CRITICAL | `test_success_after_threshold_failures_fires_critical` |
| Success clears buffer -> re-alertable | `test_success_clears_buffer_for_future_attacks` |

One non-obvious behaviour is documented explicitly: `_handle_success` does **not** evict the failure buffer -- eviction only runs when a new *failure* arrives. This means a successful login fires CRITICAL regardless of how old the prior failures are. The test `test_success_fires_critical_even_when_failures_outside_window` pins this intentional design decision so it is never silently changed.

### SQL injection: false positive elimination

The `O'Brien` case is covered at three levels:

**1. Functional test** -- confirms no incident is emitted:
```python
@pytest.mark.parametrize("query", [
    "q=O'Brien",
    "q=O'Brien's laptop",
    "q=it's a fine day",
    "q=McDonald's",
    ...
])
def test_sql_injection_no_false_positive(query, make_web):
    incidents = list(SQLInjectionRule().feed(make_web(query=query, status_code=200)))
    assert not incidents
```

**2. White-box score test** -- proves the scoring model assigns exactly 0 points to the apostrophe in a surname with no surrounding SQL structure:
```python
def test_obrien_scores_exactly_zero():
    decoded = unquote_plus("q=O'Brien")
    fired = [s.name for s in _SIGNALS if s.pattern.search(decoded)]
    assert fired == []
```

**3. URL-encoding coverage** -- confirms that percent-encoded payloads (`UNION%20SELECT`) are decoded before scoring, so attackers cannot bypass detection by encoding:
```python
pytest.param("q=UNION%20SELECT%20*%20FROM%20users", 200, Severity.CRITICAL,
             id="url_encoded_union_select")
```

### Cross-protocol correlation tests

The `CrossProtocolBruteForceRule` is a *correlation* rule: it reads shared state written by two other rules. Unit tests populate the `IPTracker` directly with `IPEvent` objects (bypassing the other rules), then assert on the incidents emitted. This isolates the correlation logic from the brute-force detection logic.

Seven threshold combinations are parametrized in a single test to verify that **both** protocols must independently meet the threshold before the rule fires:

```python
@pytest.mark.parametrize("ssh_count,web_count,threshold,expect_fire", [
    (2, 2, 2, True),   # both exactly at threshold
    (1, 2, 2, False),  # SSH below threshold -- no fire
    (2, 1, 2, False),  # web below threshold -- no fire
    (2, 2, 3, False),  # both at 2 but threshold is 3 -- no fire
    ...
])
```

### A note on IPTracker time sensitivity

`IPTracker.query()` defaults `reference_ts` to `datetime.now()` when no timestamp is provided. Tests use a fixed `BASE_TS` of `2025-07-03` -- which is more than a year before the test run date. Without explicit `reference_ts` on every query call, the TTL filter silently excluded all events and tests passed vacuously (returning empty lists). This was caught during the first test run when 8 IPTracker tests and 3 tracker-integration tests failed with `assert 0 == 1`. The fix -- always passing `reference_ts` close to the event timestamps -- is now enforced throughout the test suite and serves as a documented pitfall for anyone extending the tracker.
