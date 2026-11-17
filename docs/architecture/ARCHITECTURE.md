# BTH Cloud SOC — System Architecture \& Engineering Decisions

> \*\*Project:\*\* Beware The Hacker (BTH) Cloud Security Operations Center  
> \*\*Version:\*\* 1.0 historical prototype; Version 2 reconstruction planned  
> \*\*Platform:\*\* Microsoft Azure  
> \*\*Author:\*\* ghostshellprime | Beware The Hacker  
> \*\*Document type:\*\* Technical architecture and engineering decision record

\---

## 1\. Executive Overview

I built BTH Cloud SOC to understand how the individual components of a security operations environment connect—not simply to deploy a collection of Azure resources. The prototype uses Windows and Linux telemetry, Azure Monitor Agent (AMA), Data Collection Rules (DCRs), Azure Log Analytics, and Microsoft Sentinel to support security monitoring, investigation, detection, and incident response.

Version 1 was primarily assembled through the Azure Portal, with Bicep and ARM template work introduced as I learned the infrastructure dependencies. Version 2 will reconstruct the design as modular, repeatable infrastructure using Terraform, Azure-native Bicep where appropriate, and Ansible for configuration management.

**My engineering priorities:** centralized visibility, verifiable telemetry collection, actionable detections, safe response automation, least-privilege access, repeatable deployments, and clear evidence of what actually works.

This document distinguishes **historically exercised capabilities** from **currently verified operations** and **planned improvements**. The prototype is not represented as a production-ready managed SOC.

## 2\. Architecture at a Glance

```text
Windows VM                  Linux VM                 Azure platform
  Event Logs                 Syslog                  Activity/resource logs
      |                         |                             |
      v                         v                             |
 Azure Monitor Agent      Azure Monitor Agent                 |
      |                         |                             |
 Windows DCR                Linux DCR                         |
      |                         |                             |
      +------------+------------+                             |
                   |                                          |
                   +--------------------+---------------------+
                                        |
                                        v
                             Log Analytics Workspace
                                        |
                          +-------------+-------------+
                          |             |             |
                       KQL hunts    Sentinel      Workbooks
                                        |
                                  Analytics rules
                                        |
                                      Alerts
                                        |
                                     Incidents
                                        |
                             Investigation / triage
                                        |
                              Automation rules
                                        |
                              Logic App playbooks
                                        |
                              Approved response
```

This is a **logical diagram**. Azure platform and network logs require their own connectors, diagnostic settings, or supported ingestion paths; they do not necessarily pass through AMA. Actual routing must be validated per source.

Supporting security services include Microsoft Entra ID and Azure RBAC for access control, Network Security Groups (NSGs) and Network Watcher for network controls and diagnostics, and Defender for Cloud for posture assessment and supported workload protections.

## 3\. Azure Environment and Resource Organization

|Component|Historical name or service|Purpose|
|-|-|-|
|Resource group|`RG-Cyber-Lab`|Organize lab resources|
|Log Analytics workspace|`LAW-Cyber-Lab-0x`|Central telemetry ingestion and queries|
|Windows DCR|`DCR-Windows1`|Windows event collection policy|
|Linux DCR|Linux-specific DCR|Syslog collection policy|
|Agent|Azure Monitor Agent|Supported guest OS telemetry collection|
|SIEM|Microsoft Sentinel|Analytics, alerts, incidents, hunting|
|Network|Azure Network Watcher, NSGs|Diagnostics, flow visibility, filtering|
|Posture|Microsoft Defender for Cloud|Recommendations and posture monitoring|

The Windows DCR used the `northcentralus` region. I encountered workspace/destination selection and region-related configuration issues during implementation. That experience taught me to validate resource compatibility and deployment dependencies instead of assuming resources can always be connected simply because they exist.

A resource group is an organizational and management boundary, **not** a complete security boundary. Version 2 will use appropriate RBAC and network controls, standardized names, and tags such as `Project`, `Environment`, `Owner`, `ManagedBy`, and `CostCenter`.

Potential Version 2 separation into monitoring, network, compute, automation, and security resource groups is a design option, not an existing deployment fact. I will choose boundaries based on lifecycle and access requirements rather than adding complexity for its own sake.

## 4\. Windows Telemetry: AMA and Data Collection Rules

I selected AMA because it provides a supported, centrally configurable collection mechanism. DCRs define the relevant data sources, streams, destinations, and data flows; associations connect agent-based collection rules to target machines.

**Logical Windows path:** Windows Event Logs → AMA → associated Windows DCR → Log Analytics → KQL/Sentinel.

I created `DCR-Windows1` and worked with Windows security auditing settings. A historical Bicep resource declaration used:

```bicep
resource windowsDcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: 'DCR-Windows1'
  location: 'northcentralus'
  kind: 'Windows'
}
```

This is an illustrative excerpt, **not** a deployable complete DCR. A historical Windows security event XPath filter included:

```text
Security!\*\[System\[(band(Keywords,13510798882111488))]]
```

During testing, I learned that a healthy agent does not prove that the intended events reach the expected table. Collection configuration and streams determine whether data appears in tables such as `Event` or `SecurityEvent`. I investigated table-name mismatches and security event collection behavior rather than treating an empty query as definitive proof of agent failure.

**Historical evidence:** Windows DCR configuration, audit success/failure collection work, Log Analytics queries, and heartbeat validation. Comprehensive coverage of all targeted event IDs was **not** independently documented.

**Version 2 acceptance criteria:** deploy/onboard a Windows endpoint, install AMA, create and associate the correct DCR, generate known audit events, confirm their expected table and fields, measure latency, and save sanitized test evidence.

```kql
Heartbeat
| where TimeGenerated > ago(24h)
| summarize LastHeartbeat=max(TimeGenerated) by Computer
| order by LastHeartbeat desc
```

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| summarize Events=count() by Computer, EventID
| order by Events desc
```

The second query assumes `SecurityEvent` ingestion has been configured; heartbeat alone does not establish it.

## 5\. Linux Telemetry: Syslog Collection

**Logical Linux path:** Linux Syslog → AMA → associated Linux DCR → Log Analytics `Syslog` → KQL/Sentinel.

I created a Linux-specific DCR after working through platform-type configuration requirements. I also configured Linux Syslog collection and queried the `Syslog` table. This established the basis for monitoring authentication, privileged activity, service messages, and system events, subject to configured facilities, severities, and local logging behavior.

```kql
Syslog
| where TimeGenerated > ago(24h)
| summarize Events=count() by Computer, Facility, SeverityLevel
| order by Events desc
```

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility in\~ ("auth", "authpriv")
| project TimeGenerated, Computer, ProcessName, SeverityLevel, SyslogMessage
| order by TimeGenerated desc
```

**Version 2 acceptance criteria:** document supported Linux distributions, configure AMA and facilities, associate the DCR, generate known authentication and service events, verify ingestion, and preserve results. I will not claim complete Linux security coverage until those tests pass.

## 6\. Centralized Ingestion and Log Analytics

`LAW-Cyber-Lab-0x` was the central telemetry workspace. I chose Log Analytics because it allows different sources to be queried and correlated through Kusto Query Language (KQL). This is useful for connecting endpoint behavior with administrative activity and network evidence.

My historical KQL work included heartbeat checks, Windows and Linux event analysis, Azure VM start/stop activity, suspicious authentication patterns, DNS spikes, and network-related queries.

Example administrative activity investigation (requires `AzureActivity` ingestion):

```kql
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has\_any (
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/powerOff/action",
    "Microsoft.Compute/virtualMachines/deallocate/action")
| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue, ResourceId
| order by TimeGenerated desc
```

Cross-source exploration (requires relevant tables):

```kql
union isfuzzy=true
(
    SecurityEvent
    | where TimeGenerated > ago(24h)
    | project TimeGenerated, Computer, Source="Windows", Detail=Activity
),
(
    Syslog
    | where TimeGenerated > ago(24h)
    | project TimeGenerated, Computer, Source="Linux", Detail=SyslogMessage
)
| order by TimeGenerated desc
```

Centralizing logs improves investigations but creates retention, cost, and access-control decisions. Version 2 must define ingestion filtering, retention, diagnostic settings, table-level requirements, and budgets. Log Analytics is not by itself a complete data lake or forensics archive.

## 7\. Microsoft Sentinel: Detection and Investigation

I selected Microsoft Sentinel as the SIEM layer because it operates on top of Log Analytics and provides analytics rules, alert and incident management, hunting, workbooks, and automation integration.

**Intended workflow:** telemetry → analytics rule → alert → incident (when configured) → triage and investigation → approved response → closure and lessons learned.

During Version 1, I explored analytics rules, created incidents, wrote KQL detections/hunts, and experimented with playbooks. A KQL query is not automatically a production detection. Version 2 will give each detection a documented threat hypothesis, data dependencies, severity, entity mapping, schedule, thresholds, false-positive considerations, MITRE ATT\&CK mapping, and controlled test case.

Planned detection families include Windows authentication anomalies, Linux authentication failures, unusual Azure administrative activity, identity events, and suspicious network behavior. A detection will be called **validated** only when the required source data and expected alert/incident behavior are demonstrated.

## 8\. Incident Response and SOAR-lite

I used NIST SP 800-61 incident-handling concepts to structure how I thought about Sentinel incidents: preparation, detection and analysis, containment, eradication, recovery, and lessons learned. Version 2 will review applicable current guidance and translate it into specific procedures; referencing NIST does not establish compliance.

I manually built and experimented with Sentinel playbooks using Azure Logic Apps. This established introductory SOAR experience, not a fully tested production response platform.

I intend to automate low-risk tasks first: notifications, enrichment, tagging, and ticket creation. Disruptive actions—account disablement, host isolation, network blocks, and shutdown—require stronger authorization, explicit conditions, auditability, and rollback planning. False positives must not be allowed to cause avoidable outages.

**Version 2 test:** generate a controlled security event, verify ingestion, trigger a rule, verify the alert and incident, execute an approved playbook, and capture an end-to-end evidence record.

## 9\. Network Visibility and Security Controls

Endpoint events do not provide full network context. I explored Network Watcher, NSGs, and network analytics queries, including references to the historical `AzureNetworkAnalytics\_CL` table.

* **NSGs:** preventive inbound/outbound filtering for supported Azure subnets and interfaces.
* **Network Watcher:** diagnostics, connectivity analysis, packet capture, and supported network visibility features.
* **Flow telemetry:** connection metadata that can support investigations when the underlying collection and ingestion pipeline is configured.
* **Sentinel:** correlation and investigation of relevant ingested network events.

A queried network table does not establish full network monitoring coverage. Version 2 will use currently supported flow logging methods rather than rebuilding deprecated legacy NSG flow logging. I will validate known allowed/denied traffic, unexpected outbound activity, and connection spikes before claiming detection coverage.

## 10\. Identity, Access, and Zero Trust

I included identity hardening because security monitoring is insufficient if administrative access is overprivileged. Microsoft Entra ID handles supported identity functions; Azure RBAC governs resource actions. My target is least privilege, separation of duties, managed identities for automation, appropriate multifactor authentication, and auditable access.

Zero Trust is a design philosophy—verify explicitly, use least privilege, and assume breach—not a feature that becomes complete by enabling RBAC. IAM was part of the original prototype checklist, but the available historical evidence does not independently establish a complete tested IAM baseline. Version 2 must document actual assignments, effective permissions, identity logs, and any licensing-dependent controls.

## 11\. Defender for Cloud and Defense in Depth

I evaluated Microsoft Defender for Cloud as the posture management complement to Sentinel. Its recommendations and supported workload protections help identify weaknesses that may exist before an alert occurs.

|Layer|Service or control|Role|
|-|-|-|
|Identity|Entra ID / Azure RBAC|Authentication and authorization|
|Network|NSGs / Network Watcher|Traffic restrictions and diagnostics|
|Endpoint|AMA / operating system logs|Telemetry collection|
|Monitoring|Azure Monitor / Log Analytics|Ingestion, queries, operational visibility|
|Detection|Microsoft Sentinel|Alerts, investigations, hunting|
|Response|Sentinel / Logic Apps|Incident workflows and automation|
|Posture|Defender for Cloud|Configuration recommendations and workload security|
|Deployment|Terraform / Bicep / Ansible|Repeatability and configuration consistency|

I also investigated Azure Private Link for supported services such as Storage and Key Vault. Private connectivity is a future hardening option, not a verified historical component of the SOC. Private endpoints still require correct DNS, routing, authorization, and service configuration.

## 12\. Infrastructure as Code and Configuration as Code

Version 1 taught me the resources manually. Version 2 is about making the system reproducible.

|Tool|Intended responsibility|
|-|-|
|Terraform|Primary infrastructure provisioning and state management|
|Bicep|Azure-native resource definitions where useful|
|Ansible|Cross-platform operating system and supported software configuration|
|Git / GitHub|Change history, review, and documentation|
|KQL|Detection logic and validation queries|

I have already worked with Bicep and ARM, including Windows DCR definitions and troubleshooting diagnostic settings API versions. The full Terraform/Ansible deployment is **planned**, not already completed.

```text
Git repository
     |
     v
Terraform validation / plan / apply
     |
     v
Azure resources and permissions
     |
     v
Ansible-supported system configuration
     |
     v
AMA, DCRs, associations, connectors
     |
     v
Sentinel rules and playbooks
     |
     v
End-to-end tests and sanitized evidence
```

Version 2 will keep credentials, Terraform state, private keys, and environment secrets out of Git. Remote state, locking, identity-based deployment access, and secure secret handling will be designed explicitly. A `.gitignore` is helpful but not a substitute for secret scanning or access controls.

## 13\. Historical Validation vs. Reconstruction

|Capability|Historical work|What Version 2 must prove|
|-|-|-|
|Log Analytics|Workspace created and queried|Repeatable provisioning and ingestion|
|Windows AMA/DCR|Configured and troubleshot|Known security events arrive in correct table|
|Linux AMA/DCR|Syslog configured and queried|Known Linux events arrive with expected fields|
|Agent health|Heartbeat returned results|Health checks and failure alerting|
|KQL|Hunting and operational queries developed|Version-controlled, reproducible tests|
|Sentinel|Analytics and incidents exercised|Alert-to-incident test coverage|
|SOAR-lite|Playbooks created manually|Safe, observable response execution|
|Network|Network Watcher and network queries explored|Supported flow ingestion and test cases|
|IAM|Hardening included in lab scope|Documented least-privilege controls|
|Defender for Cloud|Posture capabilities explored|Plans, recommendations, and coverage evidenced|
|Dashboards|Monitoring/reporting explored|Documented workbooks and useful metrics|
|IaC|Bicep/ARM work performed|Terraform modules and deployment validation|
|Backup/recovery|Marked in historical checklist|Actual recovery procedure and test|

**Not yet demonstrated to a production standard:** forensic readiness, vulnerability management, formal compliance mapping, cloud cost security analysis, customer isolation, complete automation safety, service-level operations, and disaster recovery evidence.

## 14\. Version 2 Reconstruction Checklist

### Stage 1 — Core

* \[ ] Define Terraform provider, backend, naming, and tags.
* \[ ] Provision resource groups and Log Analytics.
* \[ ] Configure baseline RBAC and monitoring permissions.
* \[ ] Validate infrastructure output and resource locations.

### Stage 2 — Collection

* \[ ] Provision/onboard Windows and Linux test systems.
* \[ ] Install and verify AMA.
* \[ ] Deploy separate Windows and Linux DCRs.
* \[ ] Associate rules with the correct endpoints.
* \[ ] Generate and verify known events.
* \[ ] Capture ingestion latency and sanitized evidence.

### Stage 3 — Detection and Response

* \[ ] Configure Sentinel and required data connectors.
* \[ ] Deploy version-controlled KQL analytics rules.
* \[ ] Test alerts, entity mapping, and incident creation.
* \[ ] Deploy approved Logic App playbooks.
* \[ ] Validate non-disruptive automation and logging.

### Stage 4 — Network and Posture

* \[ ] Configure and test NSGs.
* \[ ] Enable supported network telemetry.
* \[ ] Test known network activity against collected logs.
* \[ ] Configure and document Defender for Cloud coverage.
* \[ ] Validate IAM and managed identity permissions.

### Stage 5 — Operational Readiness

* \[ ] Test redeployment and configuration drift.
* \[ ] Define log retention and cost monitoring.
* \[ ] Test backup/recovery procedures.
* \[ ] Publish validation records and known limitations.
* \[ ] Review security of automation and repository workflows.

## 15\. Validation Standard

I will not equate resource creation with operational success. Each component needs a known input, an expected result, and evidence of the actual result.

|Component|Test|Expected result|
|-|-|-|
|AMA|Query `Heartbeat`|Recent records for target system|
|Windows|Generate known audit event|Correct event/table/fields|
|Linux|Generate known Syslog event|Correct event/table/fields|
|Sentinel|Trigger controlled detection|Expected alert and incident|
|SOAR|Run approved playbook|Intended action and audit trail|
|Network|Generate controlled traffic|Relevant connection metadata|
|IAM|Review effective access|Permissions match intended roles|
|IaC|Deploy from clean configuration|Repeatable resources without secrets in Git|
|Recovery|Perform documented recovery test|Observed recovery outcome|

Evidence records will capture test ID, date, environment, configuration, procedure, expected/actual results, pass/fail status, sanitized screenshots or logs, and limitations.

## 16\. Architecture Tradeoffs

**Azure-native integration vs. portability.** Azure services integrate well but introduce platform dependencies. My AWS learning roadmap includes CloudWatch, CloudTrail, IAM, VPC Flow Logs, GuardDuty, Security Hub, and Security Lake. These are functional counterparts, not always direct replacements for Sentinel or Log Analytics.

**Visibility vs. cost.** More telemetry can improve investigations but increases ingestion and retention costs. Filtering should be guided by detection requirements and evidence needs, not simply by minimizing volume.

**Automation vs. disruption.** Automation can accelerate both correct and incorrect actions. I will prioritize non-disruptive enrichment and notifications until more consequential workflows have sufficient validation and approval controls.

**Lab vs. customer operations.** A single-environment prototype is not a multi-tenant service. A commercial deployment will require decisions about subscription ownership, tenant boundaries, customer data isolation, delegated access, billing, retention, incident escalation, and service availability.

## 17\. Architecture Decision Register

|ID|Decision|Reason|Status|
|-|-|-|-|
|ADR-001|Azure primary cloud|Integrated learning and security services|V1|
|ADR-002|Log Analytics central workspace|Cross-source KQL investigation|V1|
|ADR-003|AMA and DCRs|Standardized agent-based collection|V1|
|ADR-004|Separate OS collection rules|Windows/Linux source differences|V1|
|ADR-005|Sentinel SIEM|Analytics, hunting, incidents|V1|
|ADR-006|Logic Apps for SOAR|Sentinel workflow integration|Prototyped|
|ADR-007|Defender for Cloud|Posture visibility|Explored|
|ADR-008|Terraform primary IaC|Reproducible modular deployments|V2 planned|
|ADR-009|Retain Bicep|Azure-native implementation options|V1/V2|
|ADR-010|Ansible configuration management|Cross-platform configuration|V2 planned|
|ADR-011|Evidence-based acceptance|Separate working behavior from deployment claims|V2 planned|
|ADR-012|Low-risk automation first|Reduce false-positive disruption|V2 planned|
|ADR-013|Customer-isolated deployment model|Commercial scaling and data boundaries|Future|
|ADR-014|AI after telemetry validation|Reliable data before advanced analytics|Future|

## 18\. Repository Documentation Map

```text
BTH-Cloud-SOC/
├── README.md
├── CHANGELOG.md
├── docs/
│   ├── architecture/ARCHITECTURE.md
│   ├── implementation/
│   ├── incident-response/
│   └── validation/
├── detections/
│   ├── azure-resources/
│   ├── identity/
│   ├── linux/
│   ├── network/
│   └── windows/
├── evidence/v1/
├── infrastructure/bicep/
└── roadmap/
```

`README.md` is the project's front door. This architecture document explains why the system is designed as it is. Implementation notes will record how I deploy it, validation records will show what passed, and the detection directories will hold the actual KQL content. Terraform, Ansible, and CI/CD directories will be introduced when those implementations exist.

## 19\. Future Commercial Direction

My long-term objective is to make BTH Cloud SOC deployable for small and growing organizations, particularly businesses that need security visibility and audit-oriented evidence without operating a large internal SOC. That requires repeatable onboarding, safe automation, customer isolation, operational reporting, and clear ownership of cloud costs.

AI-assisted correlation, anomaly detection, incident summarization, and root-cause assistance are future capabilities—not features I claim the current prototype delivers. I want reliable collection, detections, and incident workflows before layering advanced analytics on top.

## 20\. Engineering Lessons and Conclusion

The most valuable lesson from Version 1 was that **a resource existing is not the same as a security capability working**. A healthy agent does not prove event coverage. An analytics query does not prove detection reliability. A playbook existing does not prove safe incident response. A successful infrastructure deployment does not prove the system works end to end.

Manual Azure work gave me the opportunity to understand the dependencies and troubleshoot the failure points. Version 2 is where I turn that understanding into code, repeatable validation, and defensible engineering evidence.

BTH Cloud SOC is both a technical portfolio and the foundation for a future security product. I want recruiters and engineers reviewing this repository to see not only the services I used, but the decisions I made, what I actually tested, where the design has limitations, and how I plan to improve it.

\---

**Maintained by:** Beware The Hacker (BTH)  
**Current milestone:** Version 1 documentation → Version 2 reconstruction  
**Next documentation:** Implementation procedures and validation evidence

