"""Advanced SID-scope regression tests for WIN-003."""

from datetime import datetime, timezone
from win003_model import detect_privileged_group_changes

BASE = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)

DOMAIN_ADMINS_SID = "S-1-5-21-100-200-300-512"
ENTERPRISE_ADMINS_SID = "S-1-5-21-100-200-300-519"
MEMBER_SID = "S-1-5-21-100-200-300-1105"


def event(event_id, group_sid):
    return {
        "timestamp": BASE,
        "event_id": event_id,
        "host": "WIN-01",
        "actor": "admin01",
        "actor_sid": "S-1-5-21-100-200-300-500",
        "member": "alice",
        "member_sid": MEMBER_SID,
        "group": "Privileged Group",
        "group_sid": group_sid,
    }


def test_domain_admins_correct_global_scope():
    findings = detect_privileged_group_changes(
        [event(4728, DOMAIN_ADMINS_SID)],
        domain_sids={DOMAIN_ADMINS_SID},
    )
    assert len(findings) == 1


def test_domain_admins_incorrect_universal_scope():
    findings = detect_privileged_group_changes(
        [event(4756, DOMAIN_ADMINS_SID)],
        domain_sids={DOMAIN_ADMINS_SID},
    )
    assert findings == []


def test_enterprise_admins_correct_universal_scope():
    findings = detect_privileged_group_changes(
        [event(4756, ENTERPRISE_ADMINS_SID)],
        domain_sids={ENTERPRISE_ADMINS_SID},
    )
    assert len(findings) == 1


def test_enterprise_admins_incorrect_global_scope():
    findings = detect_privileged_group_changes(
        [event(4728, ENTERPRISE_ADMINS_SID)],
        domain_sids={ENTERPRISE_ADMINS_SID},
    )
    assert findings == []


TESTS = [
    test_domain_admins_correct_global_scope,
    test_domain_admins_incorrect_universal_scope,
    test_enterprise_admins_correct_universal_scope,
    test_enterprise_admins_incorrect_global_scope,
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
