"""WIN-003: Event identity and deduplication regression tests."""

from datetime import datetime, timezone
from win003_model import detect_privileged_group_changes

BASE = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
ADMIN_SID = "S-1-5-32-544"


def event(record_id=None, host="DC-01", member="alice", channel="Security"):
    return {
        "timestamp": BASE,
        "event_id": 4732,
        "host": host,
        "channel": channel,
        "record_id": record_id,
        "actor": "admin01",
        "actor_sid": "S-1-5-21-100-200-300-500",
        "member": member,
        "member_sid": "S-1-5-21-100-200-300-1105",
        "group": "Administrators",
        "group_sid": ADMIN_SID,
    }


def test_duplicate_event_identity():
    findings = detect_privileged_group_changes([
        event(record_id=9001),
        event(record_id=9001),
    ])
    assert len(findings) == 1


def test_distinct_records_same_timestamp():
    findings = detect_privileged_group_changes([
        event(record_id=9001),
        event(record_id=9002, member="bob"),
    ])
    assert len(findings) == 2


def test_same_record_id_different_hosts():
    findings = detect_privileged_group_changes([
        event(record_id=9001, host="DC-01"),
        event(record_id=9001, host="DC-02"),
    ])
    assert len(findings) == 2


def test_same_record_id_different_channels():
    findings = detect_privileged_group_changes([
        event(record_id=9001, channel="Security"),
        event(record_id=9001, channel="Other"),
    ])
    assert len(findings) == 2


def test_missing_record_identity_preserves_events():
    findings = detect_privileged_group_changes([
        event(record_id=None),
        event(record_id=None),
    ])
    assert len(findings) == 2


TESTS = [
    test_duplicate_event_identity,
    test_distinct_records_same_timestamp,
    test_same_record_id_different_hosts,
    test_same_record_id_different_channels,
    test_missing_record_identity_preserves_events,
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

    print(f"\n{len(TESTS) - failures}/{len(TESTS)} tests passed.")

    if failures:
        raise SystemExit(1)
