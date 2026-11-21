
from datetime import datetime, timedelta
from win002_model import detect_success_after_failures


BASE = datetime(2026, 11, 21, 12, 0)


def event(minutes, event_id, host="WIN-01",
          account="alice", source_ip="10.0.0.5"):
    return {
        "timestamp": BASE + timedelta(minutes=minutes),
        "event_id": event_id,
        "host": host,
        "account": account,
        "source_ip": source_ip,
    }


def test_five_failures_then_success():
    events = [
        event(i, 4625) for i in range(5)
    ] + [event(5, 4624)]

    findings = detect_success_after_failures(events)

    assert len(findings) == 1
    assert findings[0]["failure_count"] == 5


def test_below_threshold():
    events = [
        event(i, 4625) for i in range(4)
    ] + [event(5, 4624)]

    assert detect_success_after_failures(events) == []


def test_different_account():
    events = [
        event(i, 4625, account="alice")
        for i in range(5)
    ] + [event(5, 4624, account="bob")]

    assert detect_success_after_failures(events) == []


def test_different_host():
    events = [
        event(i, 4625, host="WIN-01")
        for i in range(5)
    ] + [event(5, 4624, host="WIN-02")]

    assert detect_success_after_failures(events) == []


def test_different_source_ip():
    events = [
        event(i, 4625, source_ip="10.0.0.5")
        for i in range(5)
    ] + [event(5, 4624, source_ip="10.0.0.6")]

    assert detect_success_after_failures(events) == []


def test_failures_after_success():
    events = [event(0, 4624)] + [
        event(i, 4625) for i in range(1, 6)
    ]

    assert detect_success_after_failures(events) == []


def test_failures_outside_window():
    events = [
        event(i, 4625) for i in range(5)
    ] + [event(20, 4624)]

    assert detect_success_after_failures(events) == []


def test_missing_source_ip():
    events = [
        event(i, 4625, source_ip="")
        for i in range(5)
    ] + [event(5, 4624, source_ip="")]

    assert detect_success_after_failures(events) == []


def test_unsorted_input():
    events = [event(5, 4624)] + [
        event(i, 4625) for i in range(5)
    ]

    assert len(detect_success_after_failures(events)) == 1


def test_exact_window_boundary():
    events = [
        event(i, 4625) for i in range(5)
    ] + [event(10, 4624)]

    findings = detect_success_after_failures(events)

    # Failure at minute zero is excluded.
    assert findings == []


if __name__ == "__main__":
    tests = [
        (name, function)
        for name, function in sorted(globals().items())
        if name.startswith("test_") and callable(function)
    ]

    for name, function in tests:
        function()
        print(f"PASS {name}")

    print(f"\n{len(tests)} tests passed.")
