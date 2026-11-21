
"""WIN-001 v1.1 offline deduplication tests.

Validates the intended result-selection policy.
Does not execute or validate KQL.
"""

from datetime import timedelta

from test_win001 import BASE, make
from test_win001_sliding import sliding_matches


def deduplicate(matches):
    """Keep the latest qualifying window per entity."""
    results = {}

    for key, count in matches.items():
        window_end, host, account, ip = key
        entity = (host, account, ip)

        if (
            entity not in results
            or window_end > results[entity][0]
        ):
            results[entity] = (window_end, count)

    return results


def test_multiple_windows_one_result():
    matches = sliding_matches(make(5))

    assert len(matches) > 1
    assert len(deduplicate(matches)) == 1


def test_latest_window_selected():
    matches = sliding_matches(make(5))
    result = deduplicate(matches)

    latest = max(key[0] for key in matches)
    assert list(result.values())[0][0] == latest


def test_distinct_entities_preserved():
    records = (
        make(5, account="alice")
        + make(5, account="bob")
    )

    assert len(deduplicate(sliding_matches(records))) == 2


def test_below_threshold_no_result():
    assert deduplicate(sliding_matches(make(4))) == {}


def test_separate_bursts_collapsed():
    records = make(5)

    later = make(5)
    for event in later:
        event["TimeGenerated"] += timedelta(minutes=30)

    matches = sliding_matches(records + later)

    # Documents the current policy's limitation:
    # distinct bursts from the same entity are collapsed.
    assert len(deduplicate(matches)) == 1


if __name__ == "__main__":
    tests = [
        test_multiple_windows_one_result,
        test_latest_window_selected,
        test_distinct_entities_preserved,
        test_below_threshold_no_result,
        test_separate_bursts_collapsed,
    ]

    for test in tests:
        test()
        print(f"PASS {test.__name__}")
