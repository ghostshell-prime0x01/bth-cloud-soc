# Version 1 — Manual Implementation

**Project:** Beware The Hacker (BTH) Cloud SOC  
**Document path:** `docs/implementation/V1-MANUAL-IMPLEMENTATION.md`  
**Implementation model:** Azure Portal–first, manually configured proof of concept  
**Status:** Historical implementation record; reconstruction and validation planned for Version 2

## 1\. Purpose

I built Version 1 of the BTH Cloud SOC to understand how a security operations center actually works before attempting to automate its deployment. Rather than starting with a polished template, I provisioned and configured the core services through the Azure Portal, tested telemetry from Windows and Linux, worked with Kusto Query Language (KQL), and experimented with Microsoft Sentinel detections, incidents, and playbooks.

This document records **what I implemented, why I made those decisions, what I observed, and what still needs to be verified**. It is not a claim that every historical resource remains deployed or that the prototype was production-ready. Where exact settings or evidence are unavailable, I identify the gap instead of inventing a configuration.

Version 1 established my operational baseline. Version 2 will turn that knowledge into a reproducible, auditable deployment using infrastructure as code (IaC), configuration as code, and repeatable validation.

## 2\. Scope and Engineering Approach

The initial goal was a working cloud SOC prototype capable of collecting endpoint and cloud telemetry, querying security events, creating detections, and supporting basic response workflows.

My approach was iterative:

1. Deploy a minimal Azure environment.
2. Connect telemetry sources and confirm that events reach the workspace.
3. Enable Microsoft Sentinel on the Log Analytics workspace.
4. Develop KQL queries and translate useful patterns into detections.
5. Test incident handling and basic automated response.
6. Add supporting controls for identity, network visibility, monitoring, and resilience.
7. Document limitations and prepare to rebuild the environment as code.

I prioritized understanding the data path and service dependencies over making the environment look complete on paper. Several configurations required troubleshooting, especially resource-region alignment, Data Collection Rules (DCRs), and the distinction between available tables and actual ingested data.

## 3\. Environment Inventory

The following names and details come from my historical build notes and configuration examples. They are identifiers from the lab, **not a verified current Azure inventory**.

|Component|Historical implementation|Notes|
|-|-|-|
|Cloud platform|Microsoft Azure|Primary cloud for Version 1|
|Resource group|`RG-Cyber-Lab`|Main lab resource grouping|
|Log Analytics workspace|`LAW-Cyber-Lab-0x`|Central telemetry destination|
|SIEM/SOAR|Microsoft Sentinel|Connected to the Log Analytics workspace|
|Windows ingestion|Azure Monitor Agent (AMA) + Windows DCR|Security event collection tested|
|Windows DCR|`DCR-Windows1`|Bicep example uses `northcentralus`|
|Linux ingestion|AMA + Linux DCR|Syslog and Heartbeat tested|
|Cloud activity|Azure Activity Log|Used in start/stop/deallocate investigations|
|Network telemetry|Azure Network Watcher / network analytics exploration|Specific flow-log configuration needs revalidation|
|Cloud posture|Microsoft Defender for Cloud|Explored as a complementary posture/security service|
|Identity/security controls|Azure IAM / Zero Trust hardening|Historical checklist marked complete; exact controls need evidence|
|Automation|Sentinel playbooks / Logic Apps|Manual experimentation and SOAR-lite workflows|
|Dashboards|Azure Monitor / Sentinel workbooks and reporting|Historical capability; export evidence needed|

Do not store subscription IDs, tenant IDs, keys, tokens, or other sensitive customer-like values in this repository. Use sanitized resource examples and external secret management.

## 4\. Manual Provisioning Sequence

### 4.1 Azure resource organization

I began by organizing the lab under `RG-Cyber-Lab`. Keeping the SOC resources together made it easier to locate related services, understand dependencies, and eventually plan cleanup and cost controls.

I learned that resource grouping does not remove regional constraints. During the build, a region mismatch affected how my workspace and collection configuration appeared or could be selected. I corrected the mismatch and learned to verify the region and supported deployment scope of each resource before attaching services.

**Version 2 improvement:** Parameterize resource names, regions, tags, and deployment scopes; validate service compatibility before deployment.

### 4.2 Log Analytics workspace

I deployed `LAW-Cyber-Lab-0x` as the central destination for operational and security telemetry. The workspace gave me a common place to run KQL against data from multiple sources.

The engineering distinction I had to learn was that **creating a workspace does not automatically collect every useful event**. Ingestion depends on the source, agent, DCR, diagnostic setting, connector, and the destination mapping. A missing table or an empty query result can mean a collection problem rather than an absence of security activity.

**Validation performed:** I used `Heartbeat` and source-specific queries to confirm that at least some Windows/Linux telemetry was arriving during historical testing.

### 4.3 Microsoft Sentinel onboarding

I enabled Microsoft Sentinel against the Log Analytics workspace and used it as the investigation and incident-management layer. Azure Monitor and Log Analytics provided collection and querying capabilities; Sentinel added SIEM-oriented analytics, alerts, incidents, hunting workflows, and automation integrations.

I experimented with analytics rules and incidents manually. This helped me understand the difference between:

* **Raw telemetry:** The events collected from systems and services.
* **KQL hunting query:** An investigator-initiated search for suspicious behavior.
* **Analytics rule:** Scheduled or otherwise configured detection logic that can generate alerts.
* **Incident:** A case that organizes related alerts and investigation context.
* **Playbook:** An automated workflow, typically built with Azure Logic Apps, that can act on a trigger or an analyst's request.

**Version 2 improvement:** Store detections, rule configuration, playbook definitions, and incident-response procedures in source control instead of relying on portal-only state.

## 5\. Windows Endpoint Telemetry

### 5.1 Agent and DCR configuration

I configured Azure Monitor Agent for Windows and created a Windows-specific DCR. A historical Bicep resource export identifies the rule as `DCR-Windows1`, with `kind: 'Windows'` and location `northcentralus`.

That example configured `windowsEventLogs` with a Security-channel XPath query, used the `Microsoft-Event` stream, and pointed to my Log Analytics workspace. I also worked with Windows security auditing settings, including success/failure event selection.

The important lesson was that the agent, the DCR, the machine association, and the destination must all line up. Installing AMA alone is not proof that Security events are flowing.

### 5.2 Validation

I tested agent connectivity and collection with queries such as:

```kusto
Heartbeat
| summarize LastSeen = max(TimeGenerated) by Computer
| order by LastSeen desc
```

Depending on the collection stream and connector configuration, Windows events may be available in `Event`, `WindowsEvent`, or `SecurityEvent`. These are different tables and should not be treated as interchangeable.

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| summarize EventCount = count() by Computer, EventID
| order by EventCount desc
```

**Historical result:** Heartbeat and Windows security telemetry were tested during the prototype. I also encountered confusion around Windows event table names and collection configuration. I do not have enough preserved evidence to assert the final event coverage, event IDs, or ingestion rate for every endpoint.

**Version 2 acceptance criteria:** Confirm AMA health, DCR association, expected Security event IDs, timestamps, host identity, ingestion latency, and test-event correlation. Save sanitized query output as evidence.

## 6\. Linux Endpoint Telemetry

I deployed a Linux DCR after correcting the rule's platform-specific configuration. I configured AMA-based Syslog collection and used the Log Analytics workspace as the destination.

Linux validation focused on whether the agent was reporting and whether Syslog messages reached the expected table.

```kusto
Heartbeat
| where TimeGenerated > ago(24h)
| summarize LastSeen = max(TimeGenerated) by Computer, OSType
| order by LastSeen desc
```

```kusto
Syslog
| where TimeGenerated > ago(24h)
| summarize Events = count() by Computer, Facility, SeverityLevel
| order by Events desc
```

**Historical result:** I tested Linux Heartbeat and Syslog ingestion. The exact facilities, severities, collection intervals, and host inventory need to be reconstructed from saved exports or retested.

**Version 2 improvement:** Use parameterized Linux DCRs, explicit facility/severity choices, standardized machine onboarding, and automated test-event generation.

## 7\. Cloud Activity and Network Visibility

### 7.1 Azure activity investigations

I used KQL against Azure activity data to investigate operations such as VM start, power-off, and deallocation. These records helped me distinguish operating-system events from Azure control-plane activity.

```kusto
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has\_any (
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/POWEROFF/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/DEALLOCATE/ACTION"
)
| project TimeGenerated, OperationNameValue, ActivityStatusValue,
          Caller, ResourceGroup, ResourceId
| order by TimeGenerated desc
```

This query is a starting point, not a guarantee of complete audit coverage. The required Activity Log connection, event retention, and fields must be validated in the reconstructed environment.

### 7.2 Network monitoring

I explored Azure Network Watcher, network security controls, and network analytics. I also wrote queries involving the custom table `AzureNetworkAnalytics\_CL` and investigated network-related patterns such as DNS spikes.

I do **not** treat those experiments as proof that all NSG flow logs, DNS logs, or network paths were consistently captured. Some network data sources and product capabilities have changed over time, so Version 2 must select currently supported telemetry sources rather than blindly reproducing an old configuration.

**Version 2 improvement:** Define required network questions first—allowed/denied flows, suspicious destinations, DNS anomalies, and lateral movement indicators—then map each question to a supported source, collection mechanism, retention policy, and detection.

## 8\. KQL Detection Engineering and Threat Hunting

KQL became one of the most useful skills I developed in Version 1. I used it to troubleshoot ingestion, establish basic event baselines, investigate suspicious activity, and experiment with detection logic.

My historical query work included:

* VM lifecycle operations from Azure activity records.
* Windows and Linux event analysis.
* DNS activity spikes and other network anomalies.
* Impossible-travel-style identity scenarios.
* Cross-source investigations using `union` across tables such as `Syslog` and `SecurityEvent`.

A detection is only as reliable as the data feeding it. For example, impossible-travel analysis requires usable sign-in timestamps, identity context, and location information; the idea alone does not establish that a complete production detection was deployed.

I separated **query development** from **operational detection maturity**. A query that returns interesting data is not automatically a tuned analytics rule with validated severity, entity mapping, alert grouping, and false-positive handling.

**Version 2 improvement:** Maintain versioned KQL in `detections/`, document required tables and permissions, map relevant behaviors to MITRE ATT\&CK, and validate each rule against known test cases.

## 9\. Sentinel Analytics, Incidents, and SOAR-lite

I manually created and explored Sentinel playbooks and incidents. This was where I began connecting monitoring to response: a suspicious event should not end at a dashboard; it needs an investigation path and, where appropriate, a controlled response action.

My initial response model was intentionally lightweight:

1. Telemetry is ingested into Log Analytics.
2. An analytics rule evaluates the relevant data.
3. An alert and/or incident is generated when configured conditions are met.
4. An analyst reviews entities, event context, and related activity.
5. A playbook may enrich, notify, or perform an approved action.
6. The investigation is documented and closed with a disposition.

I used NIST SP 800-61 as a reference for thinking through incident handling. I did not build or validate a full enterprise incident-response program in Version 1.

**Historical result:** Manual playbook experimentation, incident creation, and basic SOAR capability were part of the prototype. The exact triggers, permissions, connectors, and action outcomes still require export and retesting.

**Version 2 safeguards:** Use least-privilege managed identities, approval gates for disruptive actions, idempotent workflows where possible, error handling, and auditable execution logs. Avoid enabling automatic isolation or destructive remediation until a test proves the behavior is safe.

## 10\. IAM, Posture, Resilience, and Dashboards

My historical project checklist marked several supporting areas complete: Zero Trust/IAM hardening, backups/disaster recovery, dashboards/reporting, and endpoint visibility. That checklist represents work performed or capabilities explored during the prototype, **not a substitute for configuration evidence or control effectiveness testing**.

For the reconstructed implementation I will verify:

|Domain|Required verification|
|-|-|
|IAM|Role assignments, privileged access, MFA/conditional access applicability, service identities, least privilege|
|Cloud posture|Defender for Cloud plans, recommendations, policy coverage, and remediation tracking|
|Resilience|What is backed up, recovery objectives, restore procedures, and successful restore tests|
|Dashboards|Workbook definitions, source tables, filters, intended audience, and screenshots/exports|
|Endpoint coverage|Expected hosts versus reporting hosts, AMA health, DCR associations, and missing data|
|Cost governance|Workspace retention, ingestion volume, budgets, alerts, and service-specific charges|

I want this project to demonstrate engineering judgment, not merely the ability to switch on Azure services. A control is only defensible when I can explain its purpose and show that it works.

## 11\. Problems Encountered and Lessons Learned

### Region and resource compatibility

A workspace/DCR region mismatch caused configuration friction. I learned to inspect regional constraints and deployment relationships early rather than treating all Azure resources as globally interchangeable.

### Agent installed versus data received

Heartbeat confirmed that an agent could communicate, but it did not by itself prove that every required security event was being collected. I began checking the source configuration, DCR, associations, streams, destination, and query table independently.

### Table names and schemas

I initially had to work through the difference between Windows event tables and security-specific tables. Version 2 will document the expected schema for every detection and fail validation when a required source is absent.

### Manual portal configuration does not scale

Portal-first configuration was useful for learning service behavior. It is less useful for reproducibility, change review, drift detection, or customer deployment. That is the core reason I am moving toward IaC and configuration as code.

### An alert is not the same as a response capability

Building an analytics rule is only one part of a SOC. Triage procedures, ownership, enrichment, response authorization, evidence handling, and lessons learned all matter. I want those operational details to be visible in the repository.

## 12\. Historical Capability Assessment

This table distinguishes my earlier self-assessment from the evidence still required for a defensible implementation record.

|Capability|Version 1 historical assessment|Evidence / next action|
|-|-|-|
|Log collection (SIEM)|Implemented/tested|Reproduce Heartbeat, Syslog, Windows events|
|Alerting and monitoring|Implemented|Export rules and verify firing conditions|
|Threat detection|Implemented at prototype level|Version KQL and test detections|
|Automated response|SOAR-lite experimented with|Export playbooks; test triggers and outcomes|
|Dashboards and reports|Marked complete historically|Recover workbooks and screenshots|
|Infrastructure as code|Initial Bicep/ARM work|Consolidate into deployable Version 2 modules|
|Zero Trust / IAM|Marked complete historically|Audit actual settings and access assignments|
|Disaster recovery / backups|Marked complete historically|Document scope and demonstrate restore|
|Endpoint detection/visibility|AMA-based telemetry tested|Distinguish AMA monitoring from full EDR protection|
|Threat hunting|Basic capability demonstrated|Save queries and investigation notes|
|Forensics readiness|Outstanding|Define evidence preservation and chain of custody|
|Vulnerability scanning|Outstanding|Select scanning scope and remediation workflow|
|Compliance mapping|Outstanding|Map controls to NIST/CIS/SOC 2 as appropriate|
|Cloud cost security analysis|Outstanding|Define budgets, retention, and cost reporting|

**Important distinction:** AMA is a telemetry collection agent; it is not itself a full endpoint detection and response product. Any future claim of EDR coverage must be supported by an actual EDR deployment and validation.

## 13\. Version 2 Reconstruction Plan

Version 2 is not simply a redeployment of the same resources. It is a transition from a manually assembled proof of concept to a repeatable engineering system.

### 13.1 Infrastructure as code

Use Bicep and/or Terraform to deploy the resource group structure, Log Analytics workspace, Sentinel onboarding, supported DCRs, diagnostic settings, monitoring resources, and related infrastructure. Keep modules small enough to test independently.

### 13.2 Configuration as code

Use Ansible where appropriate for cross-platform host configuration, agent prerequisites, and repeatable Windows/Linux setup. Azure-native settings that are better represented in IaC or policy should remain there rather than being forced into Ansible.

### 13.3 Detection and response as code

Store KQL detections, metadata, prerequisites, analytics-rule definitions, playbooks, and response procedures in the repository. Every detection should have a known data source and a reproducible test.

### 13.4 Validation and evidence

For each module, collect sanitized evidence of deployment, data ingestion, expected detections, failure handling, and cleanup. Avoid committing secrets, raw personal data, or sensitive tenant identifiers.

### 13.5 Security and cost controls

Implement least-privilege access, safe defaults, resource tags, retention controls, budget alerts, and explicit approval before potentially disruptive automated response actions.

### 13.6 Multi-cloud extensibility

Azure remains the initial implementation platform. I want the architecture and documentation to describe equivalent AWS services where useful, without implying that an AWS implementation already exists.

## 14\. Validation Checklist for Reconstruction

* \[ ] Confirm the current Azure subscription, permitted regions, and resource naming convention.
* \[ ] Deploy the Log Analytics workspace and record its retention/cost settings.
* \[ ] Enable Microsoft Sentinel and verify workspace integration.
* \[ ] Deploy Windows and Linux DCRs and associate them with test hosts.
* \[ ] Confirm AMA Heartbeat from every expected host.
* \[ ] Generate and verify known Windows security events.
* \[ ] Generate and verify known Linux Syslog events.
* \[ ] Enable and validate required Azure activity/diagnostic feeds.
* \[ ] Select and validate supported network telemetry sources.
* \[ ] Deploy at least one tested detection for each supported telemetry category.
* \[ ] Verify alert creation, entity mapping, incident generation, and triage notes.
* \[ ] Execute a non-destructive playbook test and capture its run history.
* \[ ] Export dashboards/workbooks and verify their underlying queries.
* \[ ] Review IAM assignments, managed identities, and access boundaries.
* \[ ] Test backup/restore where resilience is claimed.
* \[ ] Document ingestion volume, retention, and projected monthly cost.
* \[ ] Save sanitized evidence under `evidence/v1/` or a version-appropriate validation folder.
* \[ ] Record deployment/teardown steps and update the changelog.

## 15\. Repository Cross-References

* [`../../README.md`](../../README.md) — project overview and portfolio entry point.
* [`../architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md) — component relationships and design decisions.
* [`../architecture/RESOURCE-INVENTORY.md`](../architecture/RESOURCE-INVENTORY.md) — historical and reconstructed resources.
* [`../../detections/`](../../detections/) — version-controlled detection content.
* [`../../infrastructure/bicep/`](../../infrastructure/bicep/) — infrastructure-as-code work.
* [`../../evidence/v1/`](../../evidence/v1/) — sanitized historical evidence when available.
* [`../validation/`](../validation/) — repeatable verification procedures.
* [`../incident-response/`](../incident-response/) — operational response documentation.

## 16\. Closing Assessment

Version 1 taught me how the individual Azure security services behave when they are connected, misconfigured, tested, and troubleshot in a real lab. I worked through the difference between deploying a service and validating the data or outcome it is supposed to provide.

I am not presenting the prototype as a finished managed SOC or a production-ready commercial platform. I am presenting it as the engineering foundation for one: a hands-on implementation that gave me enough operational context to design a more reliable, automated, and eventually customer-deployable Version 2.

My next objective is to make every important part of the SOC **reproducible, measurable, reviewable, and secure by default**.

# Version 1 — Manual Implementation

**Project:** Beware The Hacker (BTH) Cloud SOC  
**Document path:** `docs/implementation/V1-MANUAL-IMPLEMENTATION.md`  
**Implementation model:** Azure Portal–first, manually configured proof of concept  
**Status:** Historical implementation record; reconstruction and validation planned for Version 2

## 1\. Purpose

I built Version 1 of the BTH Cloud SOC to understand how a security operations center actually works before attempting to automate its deployment. Rather than starting with a polished template, I provisioned and configured the core services through the Azure Portal, tested telemetry from Windows and Linux, worked with Kusto Query Language (KQL), and experimented with Microsoft Sentinel detections, incidents, and playbooks.

This document records **what I implemented, why I made those decisions, what I observed, and what still needs to be verified**. It is not a claim that every historical resource remains deployed or that the prototype was production-ready. Where exact settings or evidence are unavailable, I identify the gap instead of inventing a configuration.

Version 1 established my operational baseline. Version 2 will turn that knowledge into a reproducible, auditable deployment using infrastructure as code (IaC), configuration as code, and repeatable validation.

## 2\. Scope and Engineering Approach

The initial goal was a working cloud SOC prototype capable of collecting endpoint and cloud telemetry, querying security events, creating detections, and supporting basic response workflows.

My approach was iterative:

1. Deploy a minimal Azure environment.
2. Connect telemetry sources and confirm that events reach the workspace.
3. Enable Microsoft Sentinel on the Log Analytics workspace.
4. Develop KQL queries and translate useful patterns into detections.
5. Test incident handling and basic automated response.
6. Add supporting controls for identity, network visibility, monitoring, and resilience.
7. Document limitations and prepare to rebuild the environment as code.

I prioritized understanding the data path and service dependencies over making the environment look complete on paper. Several configurations required troubleshooting, especially resource-region alignment, Data Collection Rules (DCRs), and the distinction between available tables and actual ingested data.

## 3\. Environment Inventory

The following names and details come from my historical build notes and configuration examples. They are identifiers from the lab, **not a verified current Azure inventory**.

|Component|Historical implementation|Notes|
|-|-|-|
|Cloud platform|Microsoft Azure|Primary cloud for Version 1|
|Resource group|`RG-Cyber-Lab`|Main lab resource grouping|
|Log Analytics workspace|`LAW-Cyber-Lab-0x`|Central telemetry destination|
|SIEM/SOAR|Microsoft Sentinel|Connected to the Log Analytics workspace|
|Windows ingestion|Azure Monitor Agent (AMA) + Windows DCR|Security event collection tested|
|Windows DCR|`DCR-Windows1`|Bicep example uses `northcentralus`|
|Linux ingestion|AMA + Linux DCR|Syslog and Heartbeat tested|
|Cloud activity|Azure Activity Log|Used in start/stop/deallocate investigations|
|Network telemetry|Azure Network Watcher / network analytics exploration|Specific flow-log configuration needs revalidation|
|Cloud posture|Microsoft Defender for Cloud|Explored as a complementary posture/security service|
|Identity/security controls|Azure IAM / Zero Trust hardening|Historical checklist marked complete; exact controls need evidence|
|Automation|Sentinel playbooks / Logic Apps|Manual experimentation and SOAR-lite workflows|
|Dashboards|Azure Monitor / Sentinel workbooks and reporting|Historical capability; export evidence needed|

Do not store subscription IDs, tenant IDs, keys, tokens, or other sensitive customer-like values in this repository. Use sanitized resource examples and external secret management.

## 4\. Manual Provisioning Sequence

### 4.1 Azure resource organization

I began by organizing the lab under `RG-Cyber-Lab`. Keeping the SOC resources together made it easier to locate related services, understand dependencies, and eventually plan cleanup and cost controls.

I learned that resource grouping does not remove regional constraints. During the build, a region mismatch affected how my workspace and collection configuration appeared or could be selected. I corrected the mismatch and learned to verify the region and supported deployment scope of each resource before attaching services.

**Version 2 improvement:** Parameterize resource names, regions, tags, and deployment scopes; validate service compatibility before deployment.

### 4.2 Log Analytics workspace

I deployed `LAW-Cyber-Lab-0x` as the central destination for operational and security telemetry. The workspace gave me a common place to run KQL against data from multiple sources.

The engineering distinction I had to learn was that **creating a workspace does not automatically collect every useful event**. Ingestion depends on the source, agent, DCR, diagnostic setting, connector, and the destination mapping. A missing table or an empty query result can mean a collection problem rather than an absence of security activity.

**Validation performed:** I used `Heartbeat` and source-specific queries to confirm that at least some Windows/Linux telemetry was arriving during historical testing.

### 4.3 Microsoft Sentinel onboarding

I enabled Microsoft Sentinel against the Log Analytics workspace and used it as the investigation and incident-management layer. Azure Monitor and Log Analytics provided collection and querying capabilities; Sentinel added SIEM-oriented analytics, alerts, incidents, hunting workflows, and automation integrations.

I experimented with analytics rules and incidents manually. This helped me understand the difference between:

* **Raw telemetry:** The events collected from systems and services.
* **KQL hunting query:** An investigator-initiated search for suspicious behavior.
* **Analytics rule:** Scheduled or otherwise configured detection logic that can generate alerts.
* **Incident:** A case that organizes related alerts and investigation context.
* **Playbook:** An automated workflow, typically built with Azure Logic Apps, that can act on a trigger or an analyst's request.

**Version 2 improvement:** Store detections, rule configuration, playbook definitions, and incident-response procedures in source control instead of relying on portal-only state.

## 5\. Windows Endpoint Telemetry

### 5.1 Agent and DCR configuration

I configured Azure Monitor Agent for Windows and created a Windows-specific DCR. A historical Bicep resource export identifies the rule as `DCR-Windows1`, with `kind: 'Windows'` and location `northcentralus`.

That example configured `windowsEventLogs` with a Security-channel XPath query, used the `Microsoft-Event` stream, and pointed to my Log Analytics workspace. I also worked with Windows security auditing settings, including success/failure event selection.

The important lesson was that the agent, the DCR, the machine association, and the destination must all line up. Installing AMA alone is not proof that Security events are flowing.

### 5.2 Validation

I tested agent connectivity and collection with queries such as:

```kusto
Heartbeat
| summarize LastSeen = max(TimeGenerated) by Computer
| order by LastSeen desc
```

Depending on the collection stream and connector configuration, Windows events may be available in `Event`, `WindowsEvent`, or `SecurityEvent`. These are different tables and should not be treated as interchangeable.

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| summarize EventCount = count() by Computer, EventID
| order by EventCount desc
```

**Historical result:** Heartbeat and Windows security telemetry were tested during the prototype. I also encountered confusion around Windows event table names and collection configuration. I do not have enough preserved evidence to assert the final event coverage, event IDs, or ingestion rate for every endpoint.

**Version 2 acceptance criteria:** Confirm AMA health, DCR association, expected Security event IDs, timestamps, host identity, ingestion latency, and test-event correlation. Save sanitized query output as evidence.

## 6\. Linux Endpoint Telemetry

I deployed a Linux DCR after correcting the rule's platform-specific configuration. I configured AMA-based Syslog collection and used the Log Analytics workspace as the destination.

Linux validation focused on whether the agent was reporting and whether Syslog messages reached the expected table.

```kusto
Heartbeat
| where TimeGenerated > ago(24h)
| summarize LastSeen = max(TimeGenerated) by Computer, OSType
| order by LastSeen desc
```

```kusto
Syslog
| where TimeGenerated > ago(24h)
| summarize Events = count() by Computer, Facility, SeverityLevel
| order by Events desc
```

**Historical result:** I tested Linux Heartbeat and Syslog ingestion. The exact facilities, severities, collection intervals, and host inventory need to be reconstructed from saved exports or retested.

**Version 2 improvement:** Use parameterized Linux DCRs, explicit facility/severity choices, standardized machine onboarding, and automated test-event generation.

## 7\. Cloud Activity and Network Visibility

### 7.1 Azure activity investigations

I used KQL against Azure activity data to investigate operations such as VM start, power-off, and deallocation. These records helped me distinguish operating-system events from Azure control-plane activity.

```kusto
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has\_any (
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/POWEROFF/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/DEALLOCATE/ACTION"
)
| project TimeGenerated, OperationNameValue, ActivityStatusValue,
          Caller, ResourceGroup, ResourceId
| order by TimeGenerated desc
```

This query is a starting point, not a guarantee of complete audit coverage. The required Activity Log connection, event retention, and fields must be validated in the reconstructed environment.

### 7.2 Network monitoring

I explored Azure Network Watcher, network security controls, and network analytics. I also wrote queries involving the custom table `AzureNetworkAnalytics\_CL` and investigated network-related patterns such as DNS spikes.

I do **not** treat those experiments as proof that all NSG flow logs, DNS logs, or network paths were consistently captured. Some network data sources and product capabilities have changed over time, so Version 2 must select currently supported telemetry sources rather than blindly reproducing an old configuration.

**Version 2 improvement:** Define required network questions first—allowed/denied flows, suspicious destinations, DNS anomalies, and lateral movement indicators—then map each question to a supported source, collection mechanism, retention policy, and detection.

## 8\. KQL Detection Engineering and Threat Hunting

KQL became one of the most useful skills I developed in Version 1. I used it to troubleshoot ingestion, establish basic event baselines, investigate suspicious activity, and experiment with detection logic.

My historical query work included:

* VM lifecycle operations from Azure activity records.
* Windows and Linux event analysis.
* DNS activity spikes and other network anomalies.
* Impossible-travel-style identity scenarios.
* Cross-source investigations using `union` across tables such as `Syslog` and `SecurityEvent`.

A detection is only as reliable as the data feeding it. For example, impossible-travel analysis requires usable sign-in timestamps, identity context, and location information; the idea alone does not establish that a complete production detection was deployed.

I separated **query development** from **operational detection maturity**. A query that returns interesting data is not automatically a tuned analytics rule with validated severity, entity mapping, alert grouping, and false-positive handling.

**Version 2 improvement:** Maintain versioned KQL in `detections/`, document required tables and permissions, map relevant behaviors to MITRE ATT\&CK, and validate each rule against known test cases.

## 9\. Sentinel Analytics, Incidents, and SOAR-lite

I manually created and explored Sentinel playbooks and incidents. This was where I began connecting monitoring to response: a suspicious event should not end at a dashboard; it needs an investigation path and, where appropriate, a controlled response action.

My initial response model was intentionally lightweight:

1. Telemetry is ingested into Log Analytics.
2. An analytics rule evaluates the relevant data.
3. An alert and/or incident is generated when configured conditions are met.
4. An analyst reviews entities, event context, and related activity.
5. A playbook may enrich, notify, or perform an approved action.
6. The investigation is documented and closed with a disposition.

I used NIST SP 800-61 as a reference for thinking through incident handling. I did not build or validate a full enterprise incident-response program in Version 1.

**Historical result:** Manual playbook experimentation, incident creation, and basic SOAR capability were part of the prototype. The exact triggers, permissions, connectors, and action outcomes still require export and retesting.

**Version 2 safeguards:** Use least-privilege managed identities, approval gates for disruptive actions, idempotent workflows where possible, error handling, and auditable execution logs. Avoid enabling automatic isolation or destructive remediation until a test proves the behavior is safe.

## 10\. IAM, Posture, Resilience, and Dashboards

My historical project checklist marked several supporting areas complete: Zero Trust/IAM hardening, backups/disaster recovery, dashboards/reporting, and endpoint visibility. That checklist represents work performed or capabilities explored during the prototype, **not a substitute for configuration evidence or control effectiveness testing**.

For the reconstructed implementation I will verify:

|Domain|Required verification|
|-|-|
|IAM|Role assignments, privileged access, MFA/conditional access applicability, service identities, least privilege|
|Cloud posture|Defender for Cloud plans, recommendations, policy coverage, and remediation tracking|
|Resilience|What is backed up, recovery objectives, restore procedures, and successful restore tests|
|Dashboards|Workbook definitions, source tables, filters, intended audience, and screenshots/exports|
|Endpoint coverage|Expected hosts versus reporting hosts, AMA health, DCR associations, and missing data|
|Cost governance|Workspace retention, ingestion volume, budgets, alerts, and service-specific charges|

I want this project to demonstrate engineering judgment, not merely the ability to switch on Azure services. A control is only defensible when I can explain its purpose and show that it works.

## 11\. Problems Encountered and Lessons Learned

### Region and resource compatibility

A workspace/DCR region mismatch caused configuration friction. I learned to inspect regional constraints and deployment relationships early rather than treating all Azure resources as globally interchangeable.

### Agent installed versus data received

Heartbeat confirmed that an agent could communicate, but it did not by itself prove that every required security event was being collected. I began checking the source configuration, DCR, associations, streams, destination, and query table independently.

### Table names and schemas

I initially had to work through the difference between Windows event tables and security-specific tables. Version 2 will document the expected schema for every detection and fail validation when a required source is absent.

### Manual portal configuration does not scale

Portal-first configuration was useful for learning service behavior. It is less useful for reproducibility, change review, drift detection, or customer deployment. That is the core reason I am moving toward IaC and configuration as code.

### An alert is not the same as a response capability

Building an analytics rule is only one part of a SOC. Triage procedures, ownership, enrichment, response authorization, evidence handling, and lessons learned all matter. I want those operational details to be visible in the repository.

## 12\. Historical Capability Assessment

This table distinguishes my earlier self-assessment from the evidence still required for a defensible implementation record.

|Capability|Version 1 historical assessment|Evidence / next action|
|-|-|-|
|Log collection (SIEM)|Implemented/tested|Reproduce Heartbeat, Syslog, Windows events|
|Alerting and monitoring|Implemented|Export rules and verify firing conditions|
|Threat detection|Implemented at prototype level|Version KQL and test detections|
|Automated response|SOAR-lite experimented with|Export playbooks; test triggers and outcomes|
|Dashboards and reports|Marked complete historically|Recover workbooks and screenshots|
|Infrastructure as code|Initial Bicep/ARM work|Consolidate into deployable Version 2 modules|
|Zero Trust / IAM|Marked complete historically|Audit actual settings and access assignments|
|Disaster recovery / backups|Marked complete historically|Document scope and demonstrate restore|
|Endpoint detection/visibility|AMA-based telemetry tested|Distinguish AMA monitoring from full EDR protection|
|Threat hunting|Basic capability demonstrated|Save queries and investigation notes|
|Forensics readiness|Outstanding|Define evidence preservation and chain of custody|
|Vulnerability scanning|Outstanding|Select scanning scope and remediation workflow|
|Compliance mapping|Outstanding|Map controls to NIST/CIS/SOC 2 as appropriate|
|Cloud cost security analysis|Outstanding|Define budgets, retention, and cost reporting|

**Important distinction:** AMA is a telemetry collection agent; it is not itself a full endpoint detection and response product. Any future claim of EDR coverage must be supported by an actual EDR deployment and validation.

## 13\. Version 2 Reconstruction Plan

Version 2 is not simply a redeployment of the same resources. It is a transition from a manually assembled proof of concept to a repeatable engineering system.

### 13.1 Infrastructure as code

Use Bicep and/or Terraform to deploy the resource group structure, Log Analytics workspace, Sentinel onboarding, supported DCRs, diagnostic settings, monitoring resources, and related infrastructure. Keep modules small enough to test independently.

### 13.2 Configuration as code

Use Ansible where appropriate for cross-platform host configuration, agent prerequisites, and repeatable Windows/Linux setup. Azure-native settings that are better represented in IaC or policy should remain there rather than being forced into Ansible.

### 13.3 Detection and response as code

Store KQL detections, metadata, prerequisites, analytics-rule definitions, playbooks, and response procedures in the repository. Every detection should have a known data source and a reproducible test.

### 13.4 Validation and evidence

For each module, collect sanitized evidence of deployment, data ingestion, expected detections, failure handling, and cleanup. Avoid committing secrets, raw personal data, or sensitive tenant identifiers.

### 13.5 Security and cost controls

Implement least-privilege access, safe defaults, resource tags, retention controls, budget alerts, and explicit approval before potentially disruptive automated response actions.

### 13.6 Multi-cloud extensibility

Azure remains the initial implementation platform. I want the architecture and documentation to describe equivalent AWS services where useful, without implying that an AWS implementation already exists.

## 14\. Validation Checklist for Reconstruction

* \[ ] Confirm the current Azure subscription, permitted regions, and resource naming convention.
* \[ ] Deploy the Log Analytics workspace and record its retention/cost settings.
* \[ ] Enable Microsoft Sentinel and verify workspace integration.
* \[ ] Deploy Windows and Linux DCRs and associate them with test hosts.
* \[ ] Confirm AMA Heartbeat from every expected host.
* \[ ] Generate and verify known Windows security events.
* \[ ] Generate and verify known Linux Syslog events.
* \[ ] Enable and validate required Azure activity/diagnostic feeds.
* \[ ] Select and validate supported network telemetry sources.
* \[ ] Deploy at least one tested detection for each supported telemetry category.
* \[ ] Verify alert creation, entity mapping, incident generation, and triage notes.
* \[ ] Execute a non-destructive playbook test and capture its run history.
* \[ ] Export dashboards/workbooks and verify their underlying queries.
* \[ ] Review IAM assignments, managed identities, and access boundaries.
* \[ ] Test backup/restore where resilience is claimed.
* \[ ] Document ingestion volume, retention, and projected monthly cost.
* \[ ] Save sanitized evidence under `evidence/v1/` or a version-appropriate validation folder.
* \[ ] Record deployment/teardown steps and update the changelog.

## 15\. Repository Cross-References

* [`../../README.md`](../../README.md) — project overview and portfolio entry point.
* [`../architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md) — component relationships and design decisions.
* [`../architecture/RESOURCE-INVENTORY.md`](../architecture/RESOURCE-INVENTORY.md) — historical and reconstructed resources.
* [`../../detections/`](../../detections/) — version-controlled detection content.
* [`../../infrastructure/bicep/`](../../infrastructure/bicep/) — infrastructure-as-code work.
* [`../../evidence/v1/`](../../evidence/v1/) — sanitized historical evidence when available.
* [`../validation/`](../validation/) — repeatable verification procedures.
* [`../incident-response/`](../incident-response/) — operational response documentation.

## 16\. Closing Assessment

Version 1 taught me how the individual Azure security services behave when they are connected, misconfigured, tested, and troubleshot in a real lab. I worked through the difference between deploying a service and validating the data or outcome it is supposed to provide.

I am not presenting the prototype as a finished managed SOC or a production-ready commercial platform. I am presenting it as the engineering foundation for one: a hands-on implementation that gave me enough operational context to design a more reliable, automated, and eventually customer-deployable Version 2.

My next objective is to make every important part of the SOC **reproducible, measurable, reviewable, and secure by default**.

