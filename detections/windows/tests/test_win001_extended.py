
"""Additional offline validation tests for WIN-001."""

from datetime import timedelta

from test_win001 import BASE, make, matches


def run_test(name, test_function):
    test_function()
    print(f"PASS {name}")


def test_different_accounts():
    records = (
        make(3, account="alice")
        + make(3, account="bob")
    )
    assert matches(records) == {}


def test_successful_logons_ignored():
    records = make(5)

    for event in records:
        event["EventID"] = 4624

    assert matches(records) == {}


def test_missing_source_ip():
    records = make(5, ip="")
    result = matches(records)

    assert len(result) == 1
    assert list(result.values()) == [5]


def test_window_boundary():
    records = make(5)

    # Place three events before a 10-minute boundary
    # and two after it.
    offsets = [597, 598, 599, 600, 601]

    for event, offset in zip(records, offsets):
        event["TimeGenerated"] = BASE + timedelta(
            seconds=offset
        )

    assert matches(records) == {}


def test_different_hosts():
    records = (
        make(3, host="win-lab-01")
        + make(3, host="win-lab-02")
    )
    assert matches(records) == {}


if __name__ == "__main__":
    tests = [
        test_different_accounts,
        test_successful_logons_ignored,
        test_missing_source_ip,
        test_window_boundary,
        test_different_hosts,
    ]

    for test in tests:
        run_test(test.__name__, test)
