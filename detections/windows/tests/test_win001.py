"""Local logic checks only; does not execute KQL or validate Azure ingestion."""
from collections import Counter
from datetime import datetime, timedelta, timezone

WINDOW_SECONDS = 600
THRESHOLD = 5

def matches(records):
    counts = Counter()
    for event in records:
        if event['EventID'] != 4625:
            continue
        t = int(event['TimeGenerated'].timestamp())
        key = (event['Computer'], event['Account'], event['IpAddress'], t // WINDOW_SECONDS)
        counts[key] += 1
    return {key: count for key, count in counts.items() if count >= THRESHOLD}

BASE = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
def make(n, host='win-lab', account='labuser', ip='192.0.2.10'):
    return [dict(EventID=4625, Computer=host, Account=account, IpAddress=ip, TimeGenerated=BASE+timedelta(seconds=i)) for i in range(n)]

def test_below_threshold():
    assert matches(make(4)) == {}

def test_at_threshold():
    assert list(matches(make(5)).values()) == [5]

def test_separate_sources():
    assert matches(make(3, ip='192.0.2.10') + make(2, ip='192.0.2.11')) == {}

if __name__ == '__main__':
    for test in (test_below_threshold, test_at_threshold, test_separate_sources):
        test()
        print('PASS', test.__name__)
