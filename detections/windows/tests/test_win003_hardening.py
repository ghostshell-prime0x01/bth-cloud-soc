"""WIN-003 malformed telemetry hardening tests."""

from datetime import datetime, timezone
from win003_model import detect_privileged_group_changes

BASE = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)


def event(**overrides):
    record = {
        "timestamp": BASE,
        "event_id": 4732,
        "host": "DC-01",
        "channel": "Security",
        "record_id": 9001,
        "actor": "admin01",
        "actor_sid": "S-1-5-21-100-200-300-500",
        "member": "alice",
        "member_sid": "S-1-5-21-100-200-300-1105",
        "group": "Administrators",
        "group_sid": "S-1-5-32-544",
    }
    record.update(overrides)
    return record


def test_non_dictionary_event_rejected():
    findings = detect_privileged_group_changes([
        None,
        "malformed",
        event(),
    ])
    assert len(findings) == 1


def test_unhashable_event_id_rejected():
    findings = detect_privileged_group_changes([
        event(event_id=[4732]),
    ])
    assert findings == []


def test_non_string_group_sid_rejected():
    findings = detect_privileged_group_changes([
        event(group_sid=["S-1-5-32-544"]),
    ])
    assert findings == []


def test_invalid_record_identity_preserves_events():
    findings = detect_privileged_group_changes([
        event(record_id="invalid"),
        event(record_id="invalid"),
    ])
    assert len(findings) == 2


def test_boolean_event_id_rejected():
    findings = detect_privileged_group_changes([
        event(event_id=True),
    ])
    assert findings == []


TESTS = [
    test_non_dictionary_event_rejected,
    test_unhashable_event_id_rejected,
    test_non_string_group_sid_rejected,
    test_invalid_record_identity_preserves_events,
    test_boolean_event_id_rejected,
]


if __name__ == "__main__":
    failures = 0

    for test in TESTS:
        try:
            test()
            print(f"PASS {test.__name__}")
        except AssertionError:
            failures += 1
            print(f"FAIL {test.__name__}")
        except Exception as exc:
            failures += 1
            print(f"ERROR {test.__name__}: {type(exc).__name__}: {exc}")

    print(f"\n{len(TESTS) - failures}/{len(TESTS)} tests passed.")

    if failures:
        raise SystemExit(1)
