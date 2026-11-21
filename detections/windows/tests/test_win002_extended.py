
from datetime import datetime, timedelta
from win002_model import detect_success_after_failures

BASE = datetime(2026, 11, 21, 12, 0)


def event(seconds, event_id, host="WIN-01",
          account="alice", source_ip="10.0.0.5"):
    return {
        "timestamp": BASE + timedelta(seconds=seconds),
        "event_id": event_id,
        "host": host,
        "account": account,
        "source_ip": source_ip,
    }


def test_multiple_successes():
    events = [event(i * 30, 4625) for i in range(5)]
    events += [event(180, 4624), event(240, 4624)]

    findings = detect_success_after_failures(events)

    assert len(findings) == 2


def test_separate_failure_bursts():
    events = [event(i * 30, 4625) for i in range(5)]
    events += [event(180, 4624)]
    events += [event(900 + i * 30, 4625) for i in range(5)]
    events += [event(1080, 4624)]

    findings = detect_success_after_failures(events)

    assert len(findings) == 2
    assert all(f["failure_count"] == 5 for f in findings)


def test_unrelated_event_ids():
    events = [event(i * 30, 4634) for i in range(5)]
    events += [event(180, 4624)]

    assert detect_success_after_failures(events) == []


def test_window_boundary_precision():
    events = [
        event(0, 4625),
        event(1, 4625),
        event(2, 4625),
        event(3, 4625),
        event(4, 4625),
        event(600, 4624),
    ]

    assert detect_success_after_failures(events) == []


def test_mixed_source_ips():
    events = [
        event(0, 4625, source_ip="10.0.0.5"),
        event(30, 4625, source_ip="10.0.0.5"),
        event(60, 4625, source_ip="10.0.0.5"),
        event(90, 4625, source_ip="10.0.0.6"),
        event(120, 4625, source_ip="10.0.0.6"),
        event(180, 4624, source_ip="10.0.0.5"),
    ]

    assert detect_success_after_failures(events) == []


def test_unsorted_mixed_events():
    events = [event(180, 4624)]
    events += [event(i * 30, 4625) for i in range(5)]
    events += [event(90, 4634)]

    assert len(detect_success_after_failures(events)) == 1


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
