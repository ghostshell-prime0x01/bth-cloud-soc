# Incident Response | BTH Cloud SOC

> \*\*Project:\*\* Beware The Hacker (BTH) Cloud SOC  
> \*\*Document:\*\* `docs/incident-response/INCIDENT-RESPONSE.md`  
> \*\*Scope:\*\* Azure-first V1 engineering record and V2 operating model  
> \*\*Status:\*\* Historical V1 workflow documented; V2 automation and production controls pending validation

## Purpose

I built BTH Cloud SOC to do more than collect logs and generate alerts. A SOC has to turn suspicious activity into an investigation, make a defensible decision, and respond without destroying the evidence needed to explain what happened. This document describes how I approached incident response in my original Azure lab, what I actually validated, and how I intend to mature that workflow into a repeatable service.

My response model follows the principles of **NIST SP 800-61**, with **MITRE ATT\&CK** used to describe adversary behavior. NIST gives me the incident-handling discipline; ATT\&CK gives me a common language for the techniques I am investigating. Neither framework replaces judgment, telemetry validation, or customer authorization.

**Evidence boundary:** V1 was a manually built lab and its resource group is no longer available. I have historical notes/screenshots and previously validated queries, but I am not claiming an active production SOC, continuous monitoring, a fully tested automated containment system, or a completed forensic chain of custody. Where I describe future controls, I mark them as V2 targets.

## 1\. Operating principles

1. **Validate before escalating.** A detection is a lead, not proof of compromise.
2. **Preserve before changing.** Capture the incident context and relevant telemetry before taking disruptive action when operationally safe.
3. **Scope before containing.** Identify affected identities, hosts, resources, and time windows; do not assume a single alert represents the full incident.
4. **Use least privilege.** Response identities and playbooks should have only the permissions required for approved actions.
5. **Make decisions traceable.** Every material action should have an owner, timestamp, justification, result, and evidence reference.
6. **Separate lab validation from production readiness.** A working query or manually created playbook is not the same as an exercised end-to-end response capability.
7. **Protect availability.** Isolation, account disablement, blocking rules, and deletion can interrupt business operations; require explicit authorization and rollback plans.

## 2\. V1 architecture and incident data path

```text
Windows VM / Linux VM          Azure control plane         Azure network telemetry
        |                              |                              |
        | AMA + DCR                    | AzureActivity                | Network Watcher / NSG flows
        v                              v                              v
                     Log Analytics Workspace (LAW-Cyber-Lab-0x)
                                         |
                                         v
                                 Microsoft Sentinel
                              Analytics rules / incidents
                                         |
                                         v
                           Analyst triage + KQL investigation
                                         |
                           +-------------+-------------+
                           |                           |
                           v                           v
                    Manual response              Playbook experiments
                    and documentation            (SOAR-lite; not proof
                                                 of production automation)
```

V1 included Windows/Linux telemetry collection using Azure Monitor Agent (AMA) and Data Collection Rules (DCR), ingestion into a Log Analytics workspace, Microsoft Sentinel analytics and incidents, AzureActivity visibility, a GeoIP watchlist, and network flow investigations. I also created Sentinel playbooks manually. Those components established the foundation for investigation; they did not, by themselves, establish 24/7 operations or autonomous remediation.

### Key telemetry sources

|Source|What I use it to answer|V1 evidence / limitation|
|-|-|-|
|`Heartbeat`|Is an onboarded machine reporting? When did it last check in?|Queried in V1; not a substitute for a comprehensive health SLA|
|Windows security events|Which logons, privilege changes, and host events warrant investigation?|Windows DCR/Security XPath configured; event coverage depends on collection rules|
|`Syslog`|What is happening on Linux hosts?|Linux DCR created after selecting the Linux platform; event coverage must be revalidated|
|`AzureActivity`|Who changed Azure resources, and when?|Used for control-plane activity and VM start/stop investigations|
|`AzureNetworkAnalytics\_CL`|What flows were allowed/denied, and what was labeled suspicious?|Historical MaliciousFlow Allowed/Denied query results; legacy schema and availability must be reassessed in V2|
|Sentinel watchlist `\_GetWatchlist('geoip')`|Does an IP match my curated reference list?|Lookup verified in V1; list accuracy, refresh cadence, and false positives remain operational concerns|
|Sentinel incidents|Which correlated alerts require analyst action?|Incidents and analytics rules were configured and explored in V1|

**V2 compatibility note:** Azure networking and flow-log products evolve. I will not assume the historical `AzureNetworkAnalytics\_CL` table or legacy NSG flow-log collection is the correct path for a new deployment. I will select currently supported network telemetry, document its actual schema, and update detections accordingly.

## 3\. Incident lifecycle

I organize the response process into six practical stages. This aligns with incident-response fundamentals while allowing V2 procedures to evolve with current NIST guidance.

### 3.1 Prepare

Preparation is where response speed is won or lost. Before an incident, I need an asset inventory, identity/role assignments, a telemetry baseline, retention settings, time synchronization, known-good configurations, approved containment actions, escalation contacts, and an evidence repository.

**V1:** I built the initial collection and detection foundation, used Defender for Cloud for posture visibility, explored Sentinel playbooks, and applied NIST SP 800-61 during incident-handling exercises.

**V2 target:** Codify deployment with Bicep/Terraform and host configuration with Ansible; add incident ownership, runbooks, access reviews, log-retention decisions, evidence access controls, recovery procedures, and tabletop exercises.

### 3.2 Detect and analyze

An analytics rule or analyst hunt produces a lead. I establish the alert time, source, affected entities, observed activity, and detection logic. I then pivot across identity, endpoint, Azure control-plane, and network data to distinguish a true positive from expected administration or noisy telemetry.

I document both supporting and contradicting evidence. A GeoIP match alone is not proof of malicious intent. An allowed network flow alone is not proof of successful exploitation. Missing logs may indicate a visibility gap rather than a clean host.

### 3.3 Scope and prioritize

I identify the earliest plausible activity, related events, affected accounts/resources, potential lateral movement, and business impact. Severity is based on **impact, confidence, and urgency**, not just the severity label attached to a single alert.

|Priority|Typical conditions|Handling objective|
|-|-|-|
|P1 — Critical|Confirmed active compromise with major impact, destructive activity, or widespread privileged access|Immediate escalation and coordinated containment|
|P2 — High|Strong compromise indicators or high-value asset exposure without confirmed widespread impact|Urgent investigation and approved response|
|P3 — Medium|Credible suspicious behavior with limited known impact|Investigate, enrich, and monitor|
|P4 — Low|Low-confidence signal or informational finding|Document, tune, or close with rationale|

These are **proposed operational categories**, not measured V1 response-time commitments or customer SLAs.

### 3.4 Contain

Containment should reduce attacker freedom while preserving evidence and service availability. Depending on authorization and scope, options may include disabling a compromised identity, revoking sessions, restricting a network path, isolating a host through an approved endpoint platform, or temporarily limiting a resource's permissions.

**Never treat a Sentinel incident status change as containment.** Closing an incident does not disable an account, remove persistence, or stop an active connection.

For each action, I record the approver, exact target, expected blast radius, execution time, observed result, and rollback method. In V1, my manual playbook experimentation did not establish validated automated containment.

### 3.5 Eradicate and recover

After the threat is contained, I determine the entry point and persistence mechanism, remove unauthorized access, rotate exposed credentials where warranted, patch or rebuild affected systems, and validate that monitoring is restored. Recovery includes verifying system integrity and business functionality, not simply bringing a VM online.

Recovery should use trusted images/backups and documented change controls. I monitor for recurrence and reopen the incident if the same behavior returns.

### 3.6 Review and improve

Every meaningful incident should produce a concise timeline, root-cause assessment (including uncertainty), impact statement, actions taken, evidence references, detection gaps, and assigned follow-ups. The output should improve a detection, control, runbook, training exercise, or architecture decision.

## 4\. Sentinel triage workflow

My standard analyst sequence is:

1. Open the Sentinel incident and capture its ID, title, creation time, severity, status, analytics rule, and entities.
2. Confirm the incident's workspace, ingestion health, time range, and any analytics-rule assumptions.
3. Inspect the underlying alerts and event records. Expand the time window to identify precursor and follow-on activity.
4. Pivot into `SecurityEvent` or the actual Windows security table, `Syslog`, `AzureActivity`, `Heartbeat`, and supported network logs as applicable.
5. Enrich IPs or identities using vetted intelligence/watchlists; assess the quality and age of the intelligence.
6. Record the working hypothesis, supporting evidence, alternative explanations, and confidence level.
7. Decide whether to escalate, contain with authorization, continue monitoring, or close as benign/false positive.
8. Document the outcome and propose tuning where the detection was noisy or blind.

### Example KQL: heartbeat visibility

```kusto
Heartbeat
| where TimeGenerated > ago(24h)
| summarize LastSeen=max(TimeGenerated) by Computer
| extend MinutesSinceLastSeen=datetime\_diff('minute', now(), LastSeen)
| order by MinutesSinceLastSeen desc
```

This shows recent reporting activity. A missing row requires checking onboarding, query scope, retention, agent health, and resource state before drawing conclusions.

### Example KQL: Azure control-plane activity

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue,
          ResourceGroup, ResourceId, CorrelationId
| order by TimeGenerated desc
```

This supports timeline construction for Azure management operations. Field availability and activity semantics must be confirmed against the deployed schema.

### Example KQL: Linux authentication-related syslog

```kusto
Syslog
| where TimeGenerated > ago(24h)
| where Facility in\~ ('auth', 'authpriv')
   or ProcessName has\_any ('sshd', 'sudo')
| project TimeGenerated, Computer, Facility, ProcessName, SyslogMessage
| order by TimeGenerated desc
```

This is an investigative starting point, not a complete brute-force or credential-access detection. Syslog facility names and message formats vary by distribution and collection configuration.

### Example KQL: GeoIP watchlist lookup

```kusto
\_GetWatchlist('geoip')
| take 20
```

I verified this watchlist function in V1. Before joining it to telemetry in V2, I will inspect its actual columns and normalize IP formats. I will not invent a `SearchKey` mapping or claim an IP match without checking the deployed watchlist schema.

### Historical network investigation

I previously queried `AzureNetworkAnalytics\_CL` for flows labeled `MaliciousFlow` and reviewed allowed versus denied outcomes. Historical screenshots capture that work. Because this is a legacy table, I am intentionally not presenting a copy-and-paste V2 detection until the new network logging pipeline and fields are validated.

## 5\. Investigation playbooks

These are **analyst procedures**. They are not claims that every automated response below was deployed in V1.

### Playbook A: Suspicious authentication

**Trigger:** Unusual login behavior, repeated failures followed by success, suspicious privileged access, or identity-related alert.

**Investigate:** Confirm identity, source IP, location context, device, timestamps, authentication result, privilege level, and related changes. Compare against expected user activity and check for multiple affected accounts.

**Decision:** Escalate when the evidence indicates account takeover, unauthorized privilege use, or an active session at risk.

**Authorized response:** Revoke sessions, reset credentials, require stronger authentication, or disable the identity when warranted and approved. Preserve identity logs and record the effect of each action.

**Closure criteria:** Access is secured, suspicious sessions are addressed, scope is understood, and recovery/monitoring checks are documented.

### Playbook B: Suspicious inbound or outbound network activity

**Trigger:** Threat-intelligence match, suspicious connection pattern, or network analytics finding.

**Investigate:** Identify source/destination, protocol, port, direction, action, timestamps, associated host, and whether the flow was allowed or denied. Correlate with endpoint and identity telemetry; validate intelligence freshness.

**Decision:** Distinguish blocked attempts, legitimate traffic, scanning, and plausible compromise. Do not equate an allowed flow with data exfiltration.

**Authorized response:** Restrict a confirmed malicious path through an approved network control, investigate the host, and monitor for alternate destinations. Preserve the pre-change network configuration and a rollback plan.

**Closure criteria:** Traffic behavior is explained, affected assets are reviewed, and any control changes are validated.

### Playbook C: Suspicious Azure resource change

**Trigger:** Unexpected deployment, VM power-state change, IAM modification, security setting change, or unusual control-plane activity.

**Investigate:** Query `AzureActivity`, identify the caller and operation, inspect correlation IDs, compare with approved change records, and assess the impacted resource and permissions.

**Decision:** Determine whether the change was authorized, misconfigured, or malicious.

**Authorized response:** Revert harmful changes under change control, constrain affected identities, and preserve the activity trail.

**Closure criteria:** Intended configuration is restored, access is reviewed, and the cause of the change is documented.

### Playbook D: Endpoint or Linux host compromise

**Trigger:** Suspicious process behavior, persistence indicators, unusual privileged commands, or correlated endpoint alerts.

**Investigate:** Review relevant Windows security or Linux syslog events, host heartbeat, recent changes, network connections, and available endpoint telemetry. Record gaps where process-level evidence was not collected.

**Authorized response:** Isolate or rebuild using approved tools and procedures; preserve required evidence first when safe. Rotate credentials and check for related hosts.

**Closure criteria:** Persistence is addressed, integrity is verified, telemetry is healthy, and recurrence checks are scheduled.

## 6\. Evidence handling and forensic readiness

Forensic readiness is a **V2 gap**, not a completed V1 capability. My V1 screenshots and KQL results are useful engineering evidence, but they do not constitute a formal forensic acquisition process.

The V2 evidence workflow will require:

* Unique incident ID and evidence ID, UTC timestamps, source system, collector, and acquisition method.
* Original log exports or snapshots where supported, plus query text and time-window parameters.
* Cryptographic hashes for exported files (for example, SHA-256), with verification on transfer.
* Access-restricted, encrypted storage with retention and deletion policies aligned to applicable requirements.
* Chain-of-custody records for collection, access, transfer, and analysis.
* Explicit separation of raw evidence, analyst notes, derived artifacts, and screenshots.
* Customer-specific legal hold and notification procedures when applicable; escalation to qualified legal/compliance personnel for regulated incidents.

### Evidence record template

```text
Incident ID:
Evidence ID:
Collector / role:
Source resource / system:
Collection timestamp (UTC):
Observed event range (UTC):
Acquisition method / query:
Original filename / location:
SHA-256 hash (if applicable):
Storage location and access restrictions:
Transfer / access history:
Related finding:
Limitations:
```

## 7\. SOAR and automation boundaries

In V1, I manually created and experimented with Microsoft Sentinel playbooks. I classify this as **SOAR-lite experimentation**, not a validated autonomous response platform.

My V2 automation progression is deliberate:

|Stage|Capability|Required guardrail|
|-|-|-|
|1 — Enrichment|Add asset context, threat-intelligence lookups, and related-event summaries|Data-source validation, error handling, and audit logs|
|2 — Case management|Assign owner, standardize evidence fields, and notify responders|Deduplication, routing, and notification controls|
|3 — Human-approved response|Propose network or identity containment actions|Approval gate, least-privilege identity, target validation, rollback|
|4 — Selective automation|Execute narrowly scoped, reversible actions for high-confidence detections|Tested thresholds, rate limits, exception lists, monitoring, kill switch|

Every Logic App/playbook needs version control, test cases, secret handling through approved services, observability, and failure behavior. A failed automation must not silently close an incident or claim remediation succeeded.

## 8\. Communications and escalation

An effective incident response needs a communication path as much as it needs KQL. For a commercial SOC, I will define customer-specific contacts, escalation authority, notification triggers, reporting channels, and service boundaries **before** onboarding.

**Initial incident update template:**

```text
Incident ID / priority:
Detected (UTC):
Current status:
Affected systems / identities (known):
Observed activity and confidence:
Business impact (confirmed vs. suspected):
Actions completed:
Actions awaiting authorization:
Next investigation step:
Next update target:
Owner / escalation contact:
```

No customer notification deadline, contractual SLA, or regulatory reporting period is asserted here. Those depend on agreements, jurisdiction, incident type, and applicable obligations.

## 9\. Validation and performance measures

I will evaluate the system by whether it can consistently detect, investigate, and respond—not by the number of alerts it generates.

|Measure|Definition|V1 status|
|-|-|-|
|Telemetry coverage|Percentage of in-scope assets with required healthy log sources|Not measured as a formal KPI|
|Detection validation|Rules exercised against documented benign and adversarial test cases|Selected detection/incident workflows explored; full suite pending|
|Mean time to acknowledge (MTTA)|Time from actionable incident creation to analyst acknowledgment|No defensible baseline|
|Mean time to respond/contain|Time from defined incident milestone to approved response or containment|No defensible baseline|
|False-positive rate|Percentage of reviewed detections closed as non-malicious under a defined rubric|No defensible baseline|
|Playbook success rate|Approved runs completing expected actions with verified outcomes|No defensible baseline|
|Evidence completeness|Incidents with all required evidence and decision records|Formal process pending|
|Recovery validation|Restored services and telemetry pass defined health checks|Formal test suite pending|

I will not publish invented percentages, response times, or SOC maturity scores. V2 needs a repeatable test harness and timestamped evidence before these become credible metrics.

## 10\. V2 reconstruction and test plan

* \[ ] Rebuild the workspace, Sentinel configuration, AMA onboarding, and Windows/Linux DCRs using version-controlled infrastructure definitions.
* \[ ] Validate ingestion and required fields for each supported source, including the current network telemetry architecture.
* \[ ] Recreate analytics rules with clear hypotheses, entity mapping, suppression logic, and ATT\&CK references where applicable.
* \[ ] Establish an incident taxonomy, ownership model, escalation matrix, and customer authorization boundaries.
* \[ ] Implement evidence storage, integrity verification, retention controls, and chain-of-custody procedures.
* \[ ] Rebuild playbooks first as enrichment-only workflows; test failures, permissions, and logging.
* \[ ] Add human approval and rollback tests before enabling disruptive response actions.
* \[ ] Run controlled simulations for suspicious authentication, network traffic, Azure resource changes, and host compromise.
* \[ ] Capture KQL output, alert/incident records, playbook run histories, and post-incident reviews as sanitized evidence.
* \[ ] Measure initial MTTA, containment timelines, detection fidelity, and telemetry coverage from actual exercises.
* \[ ] Review current NIST SP 800-61 guidance and update runbooks as standards and platform features change.

### Validation record template

```text
Test ID / scenario:
Date and environment:
Expected detection:
Test activity and authorization:
Data source and query:
Observed analytics rule / incident:
Triage findings:
Response action (if authorized):
Observed result:
Evidence file path(s):
Pass / fail / partial:
Gap and remediation owner:
```

## 11\. Repository integration

This document is the operating-level incident response reference. Related material should live in the repository rather than being duplicated here:

* [`../../README.md`](../../README.md) — project overview and portfolio entry point.
* [`../architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md) — component design and engineering decisions.
* [`../architecture/RESOURCE-INVENTORY.md`](../architecture/RESOURCE-INVENTORY.md) — historical and planned resources.
* [`../implementation/V1-MANUAL-IMPLEMENTATION.md`](../implementation/V1-MANUAL-IMPLEMENTATION.md) — manual build history and reconstruction notes.
* [`../../detections/`](../../detections/) — version-controlled detection queries and rule definitions as they are added.
* [`../../evidence/v1/`](../../evidence/v1/) — sanitized historical screenshots and validation artifacts.
* [`../../roadmap/`](../../roadmap/) — future engineering work.

## 12\. Engineering assessment

V1 taught me that detection engineering and incident response are connected but not interchangeable. Getting AMA, DCRs, Log Analytics, Sentinel, network visibility, and watchlists working gave me the raw material to investigate. The harder problem is turning that material into a disciplined process that another analyst—or eventually a paying customer—can trust.

My next step is to make the process reproducible: infrastructure as code for deployment, configuration management for consistent endpoints, detection-as-code for repeatable logic, and tightly controlled SOAR for response. The end goal for BTH is an Azure-first SOC capability that can expand into AWS and support commercial service delivery without exaggerating what has been tested.

**Bottom line:** V1 demonstrated foundational visibility, incident investigation, and manual SOAR exploration. V2 must prove repeatable response execution, evidence integrity, measurable performance, and safe customer-facing operations.

