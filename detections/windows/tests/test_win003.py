
"""Initial regression tests for WIN-003."""

from datetime import datetime, timezone

from win003_model import (
    detect_privileged_group_changes,
    is_privileged_group,
)

BASE = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)

ADMIN_SID = "S-1-5-32-544"
USER_SID = "S-1-5-21-100-200-300-1105"
ACTOR_SID = "S-1-5-21-100-200-300-500"
DOMAIN_ADMINS_SID = "S-1-5-21-100-200-300-512"


def event(event_id=4732, **overrides):
    record = {
        "timestamp": BASE,
        "event_id": event_id,
        "host": "WIN-01",
        "actor": "admin01",
        "actor_sid": ACTOR_SID,
        "member": "alice",
        "member_sid": USER_SID,
        "group": "Administrators",
        "group_sid": ADMIN_SID,
    }
    record.update(overrides)
    return record


def test_local_administrators_addition():
    findings = detect_privileged_group_changes([event()])
    assert len(findings) == 1
    assert findings[0]["group_sid"] == ADMIN_SID


def test_domain_admins_configured_sid():
    findings = detect_privileged_group_changes(
        [event(4728, group_sid=DOMAIN_ADMINS_SID)],
        domain_sids={DOMAIN_ADMINS_SID},
    )
    assert len(findings) == 1


def test_domain_admins_without_configuration():
    findings = detect_privileged_group_changes(
        [event(4728, group_sid=DOMAIN_ADMINS_SID)]
    )
    assert findings == []


def test_nonprivileged_group():
    findings = detect_privileged_group_changes(
        [event(group_sid="S-1-5-32-545")]
    )
    assert findings == []


def test_unsupported_event_id():
    findings = detect_privileged_group_changes([event(4733)])
    assert findings == []


def test_missing_member_sid():
    findings = detect_privileged_group_changes(
        [event(member_sid=None)]
    )
    assert findings == []


def test_missing_group_sid():
    findings = detect_privileged_group_changes(
        [event(group_sid=None)]
    )
    assert findings == []


def test_missing_timestamp():
    findings = detect_privileged_group_changes(
        [event(timestamp=None)]
    )
    assert findings == []


def test_renamed_privileged_group():
    findings = detect_privileged_group_changes(
        [event(group="Custom-Admin-Name")]
    )
    assert len(findings) == 1


def test_actor_member_distinction():
    findings = detect_privileged_group_changes([event()])
    assert len(findings) == 1

    finding = findings[0]
    assert finding["actor"] == "admin01"
    assert finding["member"] == "alice"
    assert finding["actor_sid"] == ACTOR_SID
    assert finding["member_sid"] == USER_SID
    assert finding["actor_sid"] != finding["member_sid"]


TESTS = [
    test_local_administrators_addition,
    test_domain_admins_configured_sid,
    test_domain_admins_without_configuration,
    test_nonprivileged_group,
    test_unsupported_event_id,
    test_missing_member_sid,
    test_missing_group_sid,
    test_missing_timestamp,
    test_renamed_privileged_group,
    test_actor_member_distinction,
]


if __name__ == "__main__":
    for test in TESTS:
        test()
        print(f"PASS {test.__name__}")

    print(f"\n{len(TESTS)} tests passed.")
