
# WIN-003 — Suspicious Privileged Group Membership Changes

## Detection Overview

WIN-003 identifies Windows security events indicating that
an account was added to a privileged security group.

The objective is to detect potentially unauthorized
privilege escalation or account manipulation.

## Security Objective

Identify privileged group membership additions and preserve
sufficient context for analyst investigation.

A group membership change is not automatically malicious.
The detection identifies activity requiring investigation.

## Relevant Windows Events

- 4728 — Member added to a security-enabled global group
- 4732 — Member added to a security-enabled local group
- 4756 — Member added to a security-enabled universal group

## MITRE ATT&CK

- Tactic: Persistence / Privilege Escalation
- Technique: T1098 — Account Manipulation
- Subtechnique: T1098.007 — Additional Local or Domain Groups

## Initial Detection Logic

A finding is generated when:

1. A supported group-membership addition event occurs.
2. The target group matches a configured privileged-group
   identifier.
3. The event contains sufficient information to identify
   the affected group and added member.

Initial privileged-group examples:

- Domain Admins
- Enterprise Admins
- Schema Admins
- Administrators

Production matching should prefer verified security
identifiers (SIDs) rather than English display names.

## Required Event Context

- Event timestamp
- Event ID
- Computer / reporting host
- Actor account and SID
- Added member account and SID
- Target group name and SID

## False Positive Considerations

- Authorized administrative changes
- Approved account provisioning
- Temporary privileged access
- Automated identity management
- Emergency access procedures

## Engineering Considerations

- Built-in and domain-specific group SIDs require
  different matching strategies.
- Group names can be renamed or localized.
- Event field mappings vary by collection method.
- Group membership additions do not independently
  establish attacker intent.
- Missing identity fields must not be silently treated
  as valid privileged membership changes.

## Offline Validation Plan

- Build a Python reference model.
- Generate synthetic group-membership events.
- Test supported and unsupported event IDs.
- Test privileged and nonprivileged groups.
- Test missing member and group identifiers.
- Test actor/member distinction.
- Test duplicate records and renamed groups.
- Capture reproducible regression evidence.

## Azure Validation — Deferred

- Verify SecurityEvent schema and event fields.
- Confirm privileged-group SID mappings.
- Execute the KQL candidate in Log Analytics.
- Generate authorized group-membership changes.
- Verify detection results and entity mappings.
- Assess false positives and alert deduplication.
- Deploy and validate a Sentinel analytics rule.
- Capture live evidence.

## Current Status

**Status:** Offline engineering candidate — Azure validation pending.

### Completed

- Python reference model implemented.
- 32 offline Python regression tests passed.
- 10 static KQL source-contract tests passed.
- KQL detection candidate implemented.
- Built-in privileged-group SID matching implemented.
- Explicit domain SID allowlisting supported.
- Actor and added-member identities handled separately.
- Python event-identity deduplication tested.
- Regression and troubleshooting evidence captured.

### Known Limitations

- KQL has not been executed in Microsoft Sentinel.
- SecurityEvent column mappings remain unverified against live telemetry.
- Domain privileged-group SID allowlist is empty by default.
- KQL does not currently perform event deduplication.
- Python reference-model behavior and KQL behavior are not fully equivalent.
- Added-member account name is not currently projected by the KQL candidate.
- Other configured domain groups require additional event-scope metadata.
- No live false-positive, performance, or incident-generation validation has occurred.

### Troubleshooting Record

During offline development, regression testing exposed issues involving
privileged-group scope, event identity, and malformed telemetry.

The KQL contract-test harness also required debugging:

1. Initial mapping tests: 4/10 passed.
2. Revised regex implementation: 3/10 passed.
3. Simplified assignment inspection: 10/10 passed.

The contract-test failures originated in the test harness, not in a
demonstrated KQL execution failure.

### Remaining Validation

Before production deployment:

1. Verify SecurityEvent field mappings using actual Azure telemetry.
2. Validate KQL syntax and detection results in Log Analytics.
3. Configure authorized domain privileged-group SIDs.
4. Verify actor, member, and group entity mappings.
5. Evaluate deduplication, false positives, and query performance.
6. Deploy and validate the Microsoft Sentinel analytics rule.
7. Capture live validation evidence.

**Production readiness:** Not established.
