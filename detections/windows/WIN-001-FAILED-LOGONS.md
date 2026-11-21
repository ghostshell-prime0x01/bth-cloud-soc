# WIN-001 — Repeated Windows Authentication Failures

> **Project:** BTH Cloud SOC  
> **Phase:** 5.3 — Detection Engineering  
> **Status:** Candidate / not deployed / not Azure-validated  
> **Owner:** Ghost Shell Prime  
> **Detection file:** [`WIN-001-FAILED-LOGONS.kql`](WIN-001-FAILED-LOGONS.kql)

## Engineering objective

I am building a version-controlled detection library that I can test, tune, and eventually deploy through infrastructure as code. WIN-001 identifies repeated Windows failed logons (Security Event ID **4625**) grouped by host, account, and source IP over ten-minute windows. This is a **new V2 candidate**, not a recovered copy of a V1 Sentinel rule.

My V1 evidence includes a screenshot of a `windows-rdp-auth-fail` Sentinel Workbook. That artifact validates historical workbook visualization, **not** the underlying Event ID 4625 filtering, the RDP logon type, or this detection's logic. See [`EVIDENCE-REGISTER.md`](../../docs/validation/EVIDENCE-REGISTER.md), **BTH-V1-EV-003**.

## Detection specification

| Property | Initial setting |
| --- | --- |
| Detection ID | WIN-001 |
| Primary platform | Microsoft Sentinel / Log Analytics |
| Table | `SecurityEvent` |
| Required event | `EventID == 4625` |
| Grouping | `Computer`, `Account`, `IpAddress`, 10-minute time bin |
| Threshold | At least 5 failures per bin |
| Query lookback | 1 hour |
| ATT&CK mapping | T1110 — Brute Force (candidate mapping; behavior must be investigated) |
| Severity | Medium (proposed; tune after testing) |
| Status | Not deployed or validated in Azure V2 |

The threshold is a starting hypothesis, **not** a measured baseline. A failure spike does not establish an attack. This design focuses on repeated failures from a single source against a single account and host; it is **not** comprehensive password-spray coverage across many accounts.

## KQL

See [`WIN-001-FAILED-LOGONS.kql`](WIN-001-FAILED-LOGONS.kql). The query produces `TimeGenerated`, `Host`, `AccountName`, `SourceIP`, `FailureCount`, `FirstSeen`, `LastSeen`, and `LogonTypes`. Blank source IPs can occur for local or other logon scenarios and require investigation. Verify `Account`, `IpAddress`, and `LogonType` field availability and semantics against the actual workspace schema before deployment.

## Data prerequisites

1. A Windows test host is onboarded to Azure Monitor Agent (AMA).
2. A Windows Data Collection Rule collects the relevant security events into the intended Log Analytics workspace.
3. The `SecurityEvent` table contains current Event ID 4625 records, with fields necessary for grouping.
4. Microsoft Sentinel is connected to the workspace for later analytic-rule deployment.

**Schema caveat:** Depending on the collection connector and configuration, Windows events may instead arrive in `WindowsEvent` with different field structure. Do not assume the provided query works against that table unchanged.

## Validation plan and evidence checkpoints

| Test | Action | Expected result | Evidence |
| --- | --- | --- | --- |
| WIN-001-T01 | Confirm `SecurityEvent` schema and 4625 ingestion | Fields and recent events present | Sanitized KQL results + DCR configuration |
| WIN-001-T02 | Supply four matching synthetic records in one 10-minute bin | No result | Local test output |
| WIN-001-T03 | Supply five matching synthetic records in one 10-minute bin | One result with count 5 | Local test output |
| WIN-001-T04 | Supply five records split across different hosts/accounts/source IPs | No combined false match | Local test output |
| WIN-001-T05 | Generate authorized failed-logon events on an isolated Windows lab host | Query returns expected grouping | Dated KQL output |
| WIN-001-T06 | Create scheduled Sentinel analytics rule and safely trigger it | Alert and incident created as configured | Rule settings + incident evidence |
| WIN-001-T07 | Run negative/benign scenarios and adjust threshold | Documented false-positive analysis | Tuning notes |

A local Python simulation can validate grouping and threshold expectations, **but cannot execute or validate KQL itself**. Azure-side query execution and analytic-rule testing remain mandatory before claiming operational coverage.

## False positives and blind spots

- Forgotten passwords, expired credentials, scheduled tasks, and misconfigured services can generate repeated failures.
- NAT, proxies, missing source addresses, and inconsistent account naming can affect grouping.
- Binning on fixed ten-minute boundaries can split a burst across adjacent bins.
- This query does not correlate successes after failures, distinguish all logon types, or detect distributed password spraying.
- The `SecurityEvent` table and its retention, ingestion latency, and connector configuration determine visibility.

## Sentinel deployment checklist

- [ ] Confirm current table and schema.
- [ ] Execute the query in the target Log Analytics workspace.
- [ ] Select a scheduled rule frequency/lookback compatible with the ten-minute bins and ingestion delay; evaluate overlapping-run deduplication.
- [ ] Map account, host, and IP entities using fields actually present in results.
- [ ] Set severity, tactics/techniques, suppression, and incident grouping deliberately.
- [ ] Run safe positive and negative tests and retain results.
- [ ] Export/version-control the analytic rule definition for V2 IaC.
- [ ] Record date, workspace alias, deployment commit, test outcome, and sanitized evidence paths.

## Architecture decision note

**Decision:** Start with a simple 4625 threshold rule before building broader spray and correlation analytics.  
**Rationale:** It provides a small, explainable unit of detection engineering that can be tested and tuned.  
**Tradeoff:** Simple thresholds are noisy and can miss low-and-slow or distributed attacks.  
**Revisit when:** V2 ingestion is available and measured baseline data supports tuning.

## Status record

- [x] Detection requirements documented
- [x] Initial KQL candidate authored
- [ ] KQL executed against real Azure telemetry
- [ ] Positive and negative tests completed
- [ ] Sentinel rule deployed
- [ ] Detection evidence committed

**Engineering standard:** A committed query is a candidate detection, not proof of live protection.
