
# WIN-002 — Successful Logon After Repeated Failures

## Detection Overview

WIN-002 identifies a successful Windows authentication event
following repeated failed authentication attempts involving
the same host, account, and source IP.

The purpose is to identify potential credential-guessing
activity that may have resulted in successful authentication.

## Detection Logic

- Failure Event ID: 4625
- Success Event ID: 4624
- Failure threshold: 5
- Correlation window: 10 minutes preceding success
- Correlation keys: Host, Account, Source IP
- Data source: Windows Security events
- Target SIEM: Microsoft Sentinel

## Detection Conditions

An event sequence qualifies when:

1. At least five failed logons occur.
2. The failures involve the same host, account, and source IP.
3. All qualifying failures occur within ten minutes before
   a successful logon.
4. The successful logon matches the same correlation keys.

## MITRE ATT&CK

- Technique: T1110 — Brute Force
- Mapping status: Candidate; requires validation

## False Positive Considerations

- Legitimate users repeatedly entering incorrect passwords
- Authentication retries caused by cached credentials
- Automated services using outdated credentials
- Shared systems and authentication gateways

## Engineering Limitations

- Windows events may contain missing or inconsistent IP fields.
- Account names may require normalization.
- Logon types require evaluation before production use.
- Event timestamps may be delayed or arrive out of order.
- A successful logon does not prove an account compromise.
- Local Python tests do not validate Sentinel KQL.

## Validation Strategy

### Offline

- Build a Python reference model.
- Generate synthetic Windows authentication records.
- Test threshold and event ordering.
- Test separation of accounts, hosts, and source IPs.
- Test boundary conditions and missing fields.
- Capture reproducible test evidence.

### Azure — Deferred

- Validate SecurityEvent schema and field mappings.
- Execute the KQL candidate in Log Analytics.
- Generate controlled authentication events.
- Verify detection output and false positive behavior.
- Configure and test Sentinel analytics rule.
- Capture live telemetry and incident evidence.

## Current Status

Offline development in progress.
Azure execution and deployment deferred.


## Offline Validation Results

WIN-002 was developed using a Python reference model and
synthetic Windows authentication events.

### Test Results

- Initial regression tests: 10 PASS
- Extended regression tests: 6 PASS
- Event identity regression: 1 PASS
- Total: 17 PASS
- Exit status: 0 for all three suites

### Validated Python Model Behavior

- Five failures followed by a success
- Threshold enforcement
- Host, account, and source IP correlation
- Chronological event ordering
- Ten-minute correlation window
- Missing source IP exclusion
- Multiple qualifying successes
- Separate authentication bursts
- Duplicate-timestamp success records

### KQL Candidate Status

The KQL candidate has been written but has not been
executed against a Microsoft Sentinel workspace.

The query uses a temporary SuccessRowId to preserve
distinct successful authentication rows within one
query execution.

### Known Limitations

- Python tests do not validate KQL syntax or execution.
- SuccessRowId is not stable across query executions.
- Repeated Sentinel executions may produce duplicate alerts.
- Actual Windows SecurityEvent field mappings require validation.
- Authentication ingestion delays require investigation.
- Query performance has not been measured.
- A successful authentication does not establish compromise.

### Deployment Status

Offline reference model: Tested
KQL candidate: Written, not executed
Azure Log Analytics validation: Pending
Microsoft Sentinel deployment: Pending
Live incident evidence: Pending
