
"""Extended regression tests for WIN-003."""

from datetime import datetime, timezone

from win003_model import detect_privileged_group_changes

BASE = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)

ADMIN_SID = "S-1-5-32-544"
DOMAIN_ADMINS_SID = "S-1-5-21-100-200-300-512"
ENTERPRISE_ADMINS_SID = "S-1-5-21-100-200-300-519"
MEMBER_SID = "S-1-5-21-100-200-300-1105"


def event(event_id=4732, **overrides):
    record = {
        "timestamp": BASE,
        "event_id": event_id,
        "host": "WIN-01",
        "actor": "admin01",
        "actor_sid": "S-1-5-21-100-200-300-500",
        "member": "alice",
        "member_sid": MEMBER_SID,
        "group": "Administrators",
        "group_sid": ADMIN_SID,
    }
    record.update(overrides)
    return record


def test_sid_case_normalization():
    findings = detect_privileged_group_changes([
        event(group_sid="s-1-5-32-544")
    ])
    assert len(findings) == 1


def test_sid_whitespace_normalization():
    findings = detect_privileged_group_changes([
        event(group_sid=" S-1-5-32-544 ")
    ])
    assert len(findings) == 1


def test_malformed_sid_rejected():
    findings = detect_privileged_group_changes([
        event(group_sid="not-a-valid-sid")
    ])
    assert findings == []


def test_multiple_privileged_changes():
    findings = detect_privileged_group_changes([
        event(member="alice"),
        event(member="bob"),
    ])
    assert len(findings) == 2


def test_missing_actor_identity():
    findings = detect_privileged_group_changes([
        event(actor=None, actor_sid=None)
    ])
    assert len(findings) == 1
    assert findings[0]["actor_sid"] is None


def test_inconsistent_builtin_group_scope():
    findings = detect_privileged_group_changes([
        event(4728, group_sid=ADMIN_SID)
    ])
    assert findings == []


def test_domain_admins_global_scope():
    findings = detect_privileged_group_changes(
        [event(4728, group_sid=DOMAIN_ADMINS_SID)],
        domain_sids={DOMAIN_ADMINS_SID},
    )
    assert len(findings) == 1


def test_enterprise_admins_universal_scope():
    findings = detect_privileged_group_changes(
        [event(4756, group_sid=ENTERPRISE_ADMINS_SID)],
        domain_sids={ENTERPRISE_ADMINS_SID},
    )
    assert len(findings) == 1


TESTS = [
    test_sid_case_normalization,
    test_sid_whitespace_normalization,
    test_malformed_sid_rejected,
    test_multiple_privileged_changes,
    test_missing_actor_identity,
    test_inconsistent_builtin_group_scope,
    test_domain_admins_global_scope,
    test_enterprise_admins_universal_scope,
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

    print(
        f"\n{len(TESTS) - failures}/{len(TESTS)} tests passed."
    )

    if failures:
        raise SystemExit(1)
