
"""WIN-003: Privileged group membership change detection.

Offline reference model. Not a substitute for live Sentinel validation.
"""

SUPPORTED_EVENT_IDS = {4728, 4732, 4756}

# Event ID for additions to security-enabled local groups.
BUILTIN_GROUP_EVENT_ID = 4732

# Known Active Directory privileged group RID-to-event mappings.
# 512 = Domain Admins (global group)
# 518 = Schema Admins (universal group)
# 519 = Enterprise Admins (universal group)
DOMAIN_PRIVILEGED_RID_EVENTS = {
    "512": 4728,
    "518": 4756,
    "519": 4756,
}

# Well-known Windows privileged group SIDs.
PRIVILEGED_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
}


def is_privileged_group(group_sid, domain_sids=None):
    """Return True when a SID belongs to a monitored group."""
    if not isinstance(group_sid, str):
        return False

    sid = group_sid.strip().upper()

    if sid in PRIVILEGED_SIDS:
        return True

    if domain_sids:
        normalized = {
            value.strip().upper()
            for value in domain_sids
            if isinstance(value, str)
        }
        return sid in normalized

    return False


def detect_privileged_group_changes(events, domain_sids=None):
    """Return findings for qualifying group membership additions."""
    findings = []
    seen_event_keys = set()

    for event in events:
        # Reject malformed records before accessing their fields.
        if not isinstance(event, dict):
            continue

        # Event IDs must be integers, not lists, strings, or booleans.
        event_id = event.get("event_id")

        if type(event_id) is not int:
            continue

        if event.get("event_id") not in SUPPORTED_EVENT_IDS:
            continue

        group_sid = event.get("group_sid")
        member_sid = event.get("member_sid")
        timestamp = event.get("timestamp")

        if not group_sid or not member_sid or timestamp is None:
            continue

        if not isinstance(member_sid, str) or not member_sid.strip():
            continue

        if not is_privileged_group(group_sid, domain_sids):
            continue

        # Built-in privileged groups are local security groups.
        # Event 4732 represents additions to these groups.
        normalized_sid = group_sid.strip().upper()

        if (
            normalized_sid in PRIVILEGED_SIDS
            and event["event_id"] != BUILTIN_GROUP_EVENT_ID
        ):
            continue

# Validate known Active Directory privileged group scopes.
        # The SID must already be in the configured domain allowlist.
        if (
            normalized_sid not in PRIVILEGED_SIDS
            and domain_sids
        ):
            rid = normalized_sid.rsplit("-", 1)[-1]
            expected_event_id = DOMAIN_PRIVILEGED_RID_EVENTS.get(rid)

            if (
                expected_event_id is not None
                and event["event_id"] != expected_event_id
            ):
                continue

        # Deduplicate only when a complete source identity is available.
        # Do not use timestamps alone as event identity.
        host = event.get("host")
        channel = event.get("channel")
        record_id = event.get("record_id")

        event_key = None

        if (
            isinstance(host, str) and host.strip()
            and isinstance(channel, str) and channel.strip()
            and isinstance(record_id, int)
            and not isinstance(record_id, bool)
        ):
            event_key = (
                host.strip().casefold(),
                channel.strip().casefold(),
                record_id,
            )

        if event_key is not None:
            if event_key in seen_event_keys:
                continue

            seen_event_keys.add(event_key)

        findings.append({
            "timestamp": timestamp,
            "event_id": event["event_id"],
            "host": event.get("host"),
            "actor": event.get("actor"),
            "actor_sid": event.get("actor_sid"),
            "member": event.get("member"),
            "member_sid": member_sid,
            "group": event.get("group"),
            "group_sid": group_sid,
        })

    return findings
