
"""WIN-001 v1.1 local sliding-window behavior tests.

Models one-minute evaluation steps with ten-minute
lookback windows. Does not execute or validate KQL.
"""

from collections import Counter
from datetime import timedelta

from test_win001 import BASE, make

WINDOW_SECONDS = 600
STEP_SECONDS = 60
THRESHOLD = 5


def sliding_matches(records):
    if not records:
        return {}

    times = [
        int(event["TimeGenerated"].timestamp())
        for event in records
    ]

    first_end = (
        min(times) // STEP_SECONDS
    ) * STEP_SECONDS

    last_end = (
        max(times) // STEP_SECONDS + 1
    ) * STEP_SECONDS + WINDOW_SECONDS

    matches = {}

    for end in range(
        first_end, last_end + STEP_SECONDS,
        STEP_SECONDS
    ):
        start = end - WINDOW_SECONDS
        counts = Counter()

        for event in records:
            if event["EventID"] != 4625:
                continue

            timestamp = int(
                event["TimeGenerated"].timestamp()
            )

            if not (start < timestamp <= end):
                continue

            key = (
                event["Computer"],
                event["Account"],
                event["IpAddress"],
            )

            counts[key] += 1

        for key, count in counts.items():
            if count >= THRESHOLD:
                matches[(end, *key)] = count

    return matches


def test_boundary_spanning_detection():
    records = make(5)
    offsets = [597, 598, 599, 600, 601]

    for event, offset in zip(records, offsets):
        event["TimeGenerated"] = (
            BASE + timedelta(seconds=offset)
        )

    assert sliding_matches(records)


def test_below_threshold():
    assert sliding_matches(make(4)) == {}


def test_separate_accounts():
    records = (
        make(3, account="alice")
        + make(3, account="bob")
    )

    assert sliding_matches(records) == {}


def test_separate_hosts():
    records = (
        make(3, host="win-01")
        + make(3, host="win-02")
    )

    assert sliding_matches(records) == {}


def test_separate_source_ips():
    records = (
        make(3, ip="192.0.2.10")
        + make(3, ip="192.0.2.11")
    )

    assert sliding_matches(records) == {}


def test_successful_logons_ignored():
    records = make(5)

    for event in records:
        event["EventID"] = 4624

    assert sliding_matches(records) == {}


if __name__ == "__main__":
    tests = [
        test_boundary_spanning_detection,
        test_below_threshold,
        test_separate_accounts,
        test_separate_hosts,
        test_separate_source_ips,
        test_successful_logons_ignored,
    ]

    for test in tests:
        test()
        print(f"PASS {test.__name__}")
