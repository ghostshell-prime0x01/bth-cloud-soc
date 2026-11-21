
from datetime import timedelta

FAILURE_EVENT = 4625
SUCCESS_EVENT = 4624
THRESHOLD = 5
WINDOW = timedelta(minutes=10)


def detect_success_after_failures(events):
    """
    Detect successful Windows logons preceded by repeated failures.

    Events must contain:
        timestamp: datetime
        event_id: int
        host: str
        account: str
        source_ip: str

    Returns one finding per qualifying success event.
    """

    findings = []

    ordered_events = sorted(
        events,
        key=lambda event: event["timestamp"]
    )

    for success in ordered_events:
        if success["event_id"] != SUCCESS_EVENT:
            continue

        # Avoid correlating records without usable identity fields.
        if not all(
            success.get(field)
            for field in ("host", "account", "source_ip")
        ):
            continue

        matching_failures = [
            event
            for event in ordered_events
            if (
                event["event_id"] == FAILURE_EVENT
                and event.get("host") == success["host"]
                and event.get("account") == success["account"]
                and event.get("source_ip") == success["source_ip"]
                and success["timestamp"] - WINDOW
                < event["timestamp"]
                < success["timestamp"]
            )
        ]

        if len(matching_failures) >= THRESHOLD:
            findings.append({
                "host": success["host"],
                "account": success["account"],
                "source_ip": success["source_ip"],
                "success_time": success["timestamp"],
                "failure_count": len(matching_failures),
                "first_failure": matching_failures[0]["timestamp"],
                "last_failure": matching_failures[-1]["timestamp"],
            })

    return findings
