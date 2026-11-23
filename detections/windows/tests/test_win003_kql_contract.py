"""WIN-003 static KQL source-contract tests.

Checks intended field mappings and safety requirements.
Does not execute KQL or validate the live SecurityEvent schema.
"""

from pathlib import Path
import re

KQL_PATH = (
    Path(__file__).resolve().parents[1]
    / "WIN-003-PRIVILEGED-GROUP-CHANGES.kql"
)

KQL = KQL_PATH.read_text(encoding="utf-8")

def mapping_exists(alias, source):
    """Check a named KQL assignment references its expected source."""

    for line in KQL.splitlines():
        stripped = line.strip()

        if stripped.startswith("//"):
            continue

        if "=" not in stripped:
            continue

        left, right = stripped.split("=", 1)

        if left.strip() != alias:
            continue

        expected = f'column_ifexists("{source}"'

        return expected in right

    return False

def test_group_sid_mapping():
    assert mapping_exists("GroupSid", "TargetSid")


def test_member_sid_mapping():
    assert mapping_exists("AddedMemberSid", "MemberSid")


def test_actor_account_mapping():
    assert mapping_exists("ActorAccount", "SubjectAccount")


def test_actor_sid_mapping():
    assert mapping_exists("ActorSid", "SubjectUserSid")


def test_group_name_mapping():
    assert mapping_exists("GroupName", "TargetAccount")


def test_event_record_mapping():
    assert mapping_exists("SourceRecordId", "EventRecordId")


def test_source_channel_mapping():
    assert mapping_exists("SourceChannel", "Channel")


def test_domain_allowlist_defaults_empty():
    assert re.search(
        r"let\s+ConfiguredDomainSids\s*=\s*dynamic\(\s*\[\s*\]\s*\)",
        KQL,
    )


def test_supported_event_ids():
    assert re.search(
        r"EventID\s+in\s*\(\s*4728\s*,\s*4732\s*,\s*4756\s*\)",
        KQL,
    )


def test_no_active_deduplication():
    active_lines = [
        line.strip()
        for line in KQL.splitlines()
        if line.strip() and not line.lstrip().startswith("//")
    ]

    active_query = "\n".join(active_lines)

    assert not re.search(
        r"\|\s*(summarize|serialize|partition)\b",
        active_query,
    )


TESTS = [
    test_group_sid_mapping,
    test_member_sid_mapping,
    test_actor_account_mapping,
    test_actor_sid_mapping,
    test_group_name_mapping,
    test_event_record_mapping,
    test_source_channel_mapping,
    test_domain_allowlist_defaults_empty,
    test_supported_event_ids,
    test_no_active_deduplication,
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
