
from datetime import datetime, timedelta
from win002_model import detect_success_after_failures

BASE = datetime(2026, 11, 21, 12, 0)


def event(seconds, event_id):
    return {
        "timestamp": BASE + timedelta(seconds=seconds),
        "event_id": event_id,
        "host": "WIN-01",
        "account": "alice",
        "source_ip": "10.0.0.5",
    }


def test_duplicate_timestamp_successes():
    events = [
        event(i * 30, 4625)
        for i in range(5)
    ]

    # Two distinct success records with identical timestamps.
    events += [
        event(180, 4624),
        event(180, 4624),
    ]

    findings = detect_success_after_failures(events)

    assert len(findings) == 2
    assert all(
        finding["failure_count"] == 5
        for finding in findings
    )


if __name__ == "__main__":
    test_duplicate_timestamp_successes()
    print("PASS test_duplicate_timestamp_successes")
    print("\n1 test passed.")
