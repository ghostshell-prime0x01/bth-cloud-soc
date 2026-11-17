# BTH Cloud SOC — Azure Resource Inventory

**Project:** Beware The Hacker (BTH) Cloud SOC  
**Document:** Resource Inventory  
**Version:** 1.0  
**Environment:** Microsoft Azure — Version 1 Prototype  
**Status:** Historical Inventory / Version 2 Reconstruction Pending  
**Last Updated:** November 2026

\---

## 1\. Overview

This document inventories the Azure resources, security services, and supporting infrastructure I used while developing my BTH Cloud Security Operations Center (SOC).

I built Version 1 primarily through the Azure Portal to understand the underlying services before automating them. This inventory records what I implemented, what I validated, what remains unverified, and what needs to be reconstructed in Version 2. It also establishes a foundation for repeatable deployments and, eventually, a commercial SOC offering.

This is a **historical engineering inventory**, not a live Azure subscription export. I have intentionally marked unknown configuration values rather than inventing them.

### Objectives

* Identify the services and resources supporting the prototype.
* Explain each component's operational role and dependencies.
* Preserve known names, regions, and validation outcomes.
* Separate deployed capabilities from concepts I evaluated.
* Identify gaps requiring discovery or reconstruction.
* Prepare the environment for IaC, configuration management, validation, and cost tracking.

\---

## 2\. Environment Profile

|Attribute|Recorded Configuration|
|-|-|
|Cloud provider|Microsoft Azure|
|Environment|Security engineering lab / SOC prototype|
|Resource group|`RG-Cyber-Lab`|
|Log Analytics workspace|`LAW-Cyber-Lab-0x`|
|SIEM|Microsoft Sentinel|
|Telemetry platform|Azure Monitor / Log Analytics|
|Endpoint platforms|Windows and Linux|
|Collection agent|Azure Monitor Agent (AMA)|
|Collection configuration|Data Collection Rules (DCRs)|
|Query language|Kusto Query Language (KQL)|
|Initial deployment|Azure Portal, ARM templates, Bicep experimentation|
|Version 2 direction|Modular IaC with Terraform/Bicep and Ansible|
|Known Windows DCR region|`northcentralus`|
|Subscription ID|Not recorded; verify privately in Azure|

**Naming convention:** The original resource names reflect my prototype. In Version 2, I intend to standardize names by resource type, workload, environment, and region. Subscription IDs, tenant IDs, secrets, and customer-specific identifiers should not be published in this repository.

\---

## 3\. Resource Inventory at a Glance

|Component|Azure Resource Type / Service|Historical State|Verification Needed|
|-|-|-|-|
|Resource group|`Microsoft.Resources/resourceGroups`|Implemented|Current contents and region metadata|
|Log Analytics workspace|`Microsoft.OperationalInsights/workspaces`|Implemented|Retention, region, tables, cost settings|
|Windows VM|`Microsoft.Compute/virtualMachines`|Monitored|Name, size, OS, region|
|Linux VM|`Microsoft.Compute/virtualMachines`|Monitored|Name, size, OS, region|
|Azure Monitor Agent|VM extension / agent|Implemented|Version and endpoint associations|
|Windows DCR|`Microsoft.Insights/dataCollectionRules`|Configured|Name, streams, XPath filters|
|Linux DCR|`Microsoft.Insights/dataCollectionRules`|Configured|Name, facilities, severities|
|DCR associations|`Microsoft.Insights/dataCollectionRuleAssociations`|Used in collection design|Exact associations|
|Microsoft Sentinel|Sentinel service on workspace|Implemented|Current enablement and configuration|
|Analytics rules|Sentinel security content|Implemented|Rule exports and settings|
|Incidents|Sentinel incidents|Used|Historical evidence|
|Playbooks|Azure Logic Apps / Sentinel|Manually created|Workflow definitions and permissions|
|Workbooks|Azure Monitor / Sentinel workbooks|Historical dashboards|Actual workbook inventory|
|Watchlists|Sentinel watchlists|Historical use|Names and schemas|
|Azure Activity Log|Azure platform telemetry|Queried|Current collection / retention|
|Network Watcher|Azure network diagnostics|Explored / used|Enabled features and flow sources|
|Defender for Cloud|Cloud security posture / protection|Evaluated / used|Enabled plans and findings|
|Entra ID / Azure RBAC|Identity and access controls|IAM hardening work|Exact roles and scopes|
|Storage accounts|`Microsoft.Storage/storageAccounts`|Evaluated|Whether deployed|
|Key Vault|`Microsoft.KeyVault/vaults`|Evaluated|Whether deployed|
|Backup / recovery|Azure backup capabilities|Historical milestone|Policies and restore evidence|
|Private Link / endpoints|Private connectivity|Evaluated|Not confirmed deployed|

**Status terminology:** *Implemented* means I historically configured or used the capability. *Validated* means I observed a supporting test result. *Evaluated* means I investigated the service but cannot claim a completed deployment. *Verification needed* means the current state or exact configuration is not established.

\---

## 4\. Resource Management

### 4.1 Resource Group — `RG-Cyber-Lab`

**Type:** `Microsoft.Resources/resourceGroups`  
**Role:** Logical management boundary for the lab.

I used this resource group to organize related SOC infrastructure. A resource group gives me a consistent boundary for deployment, access management, lifecycle operations, and resource discovery.

**Version 2 decision:** Evaluate separate groups for core monitoring, endpoints, networking, automation, and shared security services. I do not want to split resources merely for appearance; the boundaries should reflect operational ownership, permissions, and lifecycle needs.

### 4.2 Subscription and Resource Organization

The Azure subscription provides the billing and administrative boundary. I need to verify the current subscription scope, resource providers, policy assignments, tags, and RBAC inheritance before reconstructing the environment.

I will use non-sensitive tags such as `environment`, `workload`, `owner`, and `cost-center` where appropriate. I will not store privileged subscription details in public documentation.

\---

## 5\. Centralized Logging and Telemetry

### 5.1 Log Analytics Workspace — `LAW-Cyber-Lab-0x`

**Type:** `Microsoft.OperationalInsights/workspaces`  
**Role:** Central telemetry ingestion, storage, and KQL querying.

This workspace was the foundation of the SOC. I wanted Windows and Linux activity available in one place rather than investigating each machine independently. It also supplied the data platform for Microsoft Sentinel.

**Historically validated:**

* Queried endpoint heartbeat records.
* Tested Windows security event collection.
* Tested Linux Syslog collection.
* Used KQL for monitoring, hunting, and detection development.
* Investigated missing tables and ingestion configuration issues.

**Known lesson:** I encountered a regional mismatch while configuring a DCR and workspace destination. Correcting resource-region compatibility was necessary to proceed. I also learned to verify actual table names and ingestion streams instead of assuming that a query target exists.

**Version 2 requirements:** Parameterized deployment, explicit region, retention settings, access controls, ingestion-cost monitoring, and repeatable table-level validation.

### 5.2 Azure Monitor Agent

**Role:** Collect supported operating-system telemetry from monitored endpoints.

AMA is the collection mechanism. It is not a complete EDR product, and agent heartbeat data does not prove that every intended log stream is arriving.

I will separately validate agent health, DCR associations, data source configuration, and event ingestion in Version 2.

### 5.3 Windows Data Collection Rule

**Type:** `Microsoft.Insights/dataCollectionRules`  
**Platform:** Windows  
**Recorded region:** `northcentralus`  
**State:** Historically configured.

The Windows DCR defined the collection of Windows event data, including security auditing activity. I worked with success/failure auditing settings and explored a Bicep definition for Windows collection.

**To recover:** Exact DCR name, Windows event XPath filters, streams, workspace destination, data flows, and VM association.

### 5.4 Linux Data Collection Rule

**Type:** `Microsoft.Insights/dataCollectionRules`  
**Platform:** Linux  
**State:** Historically configured.

I created a Linux-specific DCR and configured Syslog collection. Selecting the appropriate platform type mattered because it determined which data source options were available.

**To recover:** DCR name, facilities, severity levels, destination, data flows, and endpoint association.

### 5.5 Monitored Windows and Linux Endpoints

The Windows VM provided security event and agent health telemetry. The Linux VM provided Syslog and heartbeat data. Both were used to understand how endpoint activity becomes centralized security information.

The original VM names, sizes, operating system versions, virtual networks, subnets, and IP configurations need to be verified before they can be represented as an authoritative asset inventory.

\---

## 6\. Microsoft Sentinel and SOC Operations

### 6.1 Microsoft Sentinel

**Role:** SIEM, detection engineering, investigation, threat hunting, and incident workflows.

I selected Sentinel because it integrates with the Log Analytics workspace and supports the operational workflow I wanted to build: collect telemetry, identify suspicious behavior, investigate, and respond.

**Historically implemented or practiced:**

* Analytics and detection rules.
* Security alerting and incident handling.
* KQL investigations and threat hunting.
* Workbooks and reporting.
* Watchlist/reference-data concepts.
* Automation and playbook experimentation.

### 6.2 Analytics Rules

I developed detections using KQL and explored telemetry from endpoints, Azure control-plane activity, and network datasets. The historical rules need to be exported or rebuilt before I can claim a reproducible detection catalog.

Version 2 detections should document the objective, data prerequisites, query, schedule, threshold, severity, MITRE ATT\&CK mapping where appropriate, test method, and false-positive considerations.

### 6.3 Incidents and Response

I used Sentinel incidents and drew on NIST SP 800-61 for incident handling. The important engineering distinction is that an alert is not the same thing as a complete investigation or response process.

Version 2 will document triage, enrichment, investigation, escalation, containment decisions, evidence preservation, and closure criteria.

### 6.4 Workbooks and Watchlists

I worked with dashboards and reference data as part of the prototype. The exact workbook names, visualization definitions, watchlist schemas, and stored entries are not presently verified.

These artifacts should be exported or reconstructed as version-controlled, non-sensitive content.

\---

## 7\. Security Automation and SOAR-Lite

|Component|Role|State|
|-|-|-|
|Sentinel automation rules|Trigger eligible automated workflows|Historical experimentation|
|Sentinel playbooks|Orchestrate incident response tasks|Manually created|
|Azure Logic Apps|Workflow execution underlying playbooks|Used through Sentinel playbooks|

I manually created and tested playbooks to understand how incident response can move beyond repetitive portal actions. My objective is to automate routine work without making high-impact security decisions blindly.

Potential response patterns include notifications, enrichment, classification, escalation, evidence gathering, and conditional remediation. **These are target capabilities, not a claim that every action existed in Version 1.**

For Version 2 I need to recover workflow triggers, connectors, actions, managed identities or connections, permissions, error handling, and run history. Disruptive actions should require appropriate approval and testing.

\---

## 8\. Network Visibility and Security

### 8.1 Network Watcher and Network Telemetry

I investigated Azure Network Watcher and how it differs from Azure Monitor. Network Watcher provides network-specific diagnostic capabilities, while Azure Monitor supports broader monitoring and log analysis.

My historical KQL work referenced `AzureNetworkAnalytics\_CL`. Referencing this table does **not** prove that the corresponding network telemetry is currently being ingested.

**Version 2 verification:** VNet inventory, subnet CIDRs, NSGs and rules, route tables, network diagnostic configuration, supported flow logging, and actual telemetry ingestion.

### 8.2 Private Link and Private Endpoints

I evaluated Private Link for securing access to supported PaaS services such as Azure Storage and Key Vault. These are architectural candidates, **not verified deployed resources**.

Private connectivity will be considered where it improves isolation and is justified by cost, operational complexity, and customer requirements.

\---

## 9\. Identity, Access, and Security Posture

### 9.1 Microsoft Entra ID and Azure RBAC

Identity and least-privilege access were part of my Zero Trust and IAM hardening work. Exact historical assignments are not yet inventoried.

**Version 2 requirements:** Enumerate privileged roles and scopes, review inherited permissions, use managed identities where supported, separate deployment and runtime permissions, and document service-to-service authentication.

### 9.2 Microsoft Defender for Cloud

I evaluated Defender for Cloud as a cloud security posture and workload protection service, distinct from Azure Monitor's telemetry role and Sentinel's SIEM role.

The enabled Defender plans, recommendations, assessments, and remediation history must be verified. A complete vulnerability scanning program and compliance mapping program were **not** finished in Version 1.

\---

## 10\. Storage, Secrets, Backup, and Forensics

|Service / Capability|Intended Role|Evidence State|
|-|-|-|
|Azure Storage|Evidence, exported logs, and supporting artifacts|Deployment unverified|
|Azure Key Vault|Secrets, keys, and certificates|Evaluated; deployment unverified|
|Backup and recovery|Restore infrastructure and data|Historical milestone; configuration unverified|
|Forensic evidence retention|Preserve investigation artifacts with integrity controls|Incomplete|

For a commercial SOC, these capabilities must be defined rather than assumed. I intend to document retention, encryption, access boundaries, backup policies, recovery objectives, restore tests, and chain-of-custody considerations.

A Log Analytics workspace is not automatically a complete forensic evidence repository or a general-purpose data lake.

\---

## 11\. Telemetry Table Inventory

|Table / Dataset|Source|Historical Evidence|
|-|-|-|
|`Heartbeat`|Agent health|Queried successfully|
|`Syslog`|Linux system logs|Collection configured and tested|
|`SecurityEvent`|Windows security auditing|Tested; exact scope requires verification|
|`WindowsEvent`|Windows event logs|Investigated; table presence unverified|
|`AzureActivity`|Azure control-plane activity|Used in KQL queries|
|`AzureNetworkAnalytics\_CL`|Legacy network analytics dataset|Referenced in historical query development|
|`SigninLogs`|Entra sign-in activity|Future integration; not confirmed|
|`AuditLogs`|Entra audit activity|Future integration; not confirmed|

A table name in a query is not proof that the table exists or contains data. Version 2 will verify schema, event freshness, volume, source coverage, and retention.

### Basic Validation Queries

**Agent heartbeat:**

```kql
Heartbeat
| summarize LastHeartbeat = max(TimeGenerated) by Computer
| order by LastHeartbeat desc
```

**Windows security events:**

```kql
SecurityEvent
| summarize EventCount = count() by Computer, EventID
| order by EventCount desc
```

**Linux Syslog:**

```kql
Syslog
| summarize EventCount = count() by Computer, Facility, SeverityLevel
| order by EventCount desc
```

**Azure resource activity:**

```kql
AzureActivity
| summarize ActivityCount = count() by OperationNameValue, ActivityStatusValue
| order by ActivityCount desc
```

\---

## 12\. Architecture Dependencies

```text
Windows / Linux Endpoints
          |
          v
Azure Monitor Agent
          |
          | configured by
          v
Data Collection Rules + Associations
          |
          v
Log Analytics Workspace
          |
          v
Microsoft Sentinel
          |
          +--> Analytics Rules --> Alerts / Incidents
          |
          +--> Hunting Queries / Workbooks
          |
          +--> Automation Rules / Playbooks
                                |
                                v
                       Investigation / Response
```

This is a **logical data and operations flow**, not a network topology. DCRs configure collection and routing; they are not separate telemetry-processing servers.

### Deployment Dependencies

1. Subscription permissions and resource providers.
2. Resource group and shared infrastructure.
3. Log Analytics workspace.
4. Sentinel enablement and configuration.
5. Endpoint deployment or registration.
6. AMA, DCRs, and associations.
7. Ingestion validation.
8. Detection and hunting content.
9. Automation workflows and permissions.
10. Dashboards, reporting, and end-to-end testing.

The precise deployment sequence will follow the dependencies in the final IaC modules.

\---

## 13\. Infrastructure as Code and Configuration Management

I experimented with ARM templates and Bicep during Version 1, including DCR deployment and diagnostic configuration. Troubleshooting API-version and resource-definition issues helped me understand why repeatable infrastructure needs explicit dependencies and validation.

|Technology|Responsibility|Project State|
|-|-|-|
|Azure Portal|Manual provisioning and exploration|Used in Version 1|
|ARM templates|Declarative Azure deployments|Experimented / used|
|Bicep|Azure resource definitions|Experimented / used|
|Terraform|Reusable infrastructure modules|Planned for Version 2|
|Ansible|Cross-platform OS and software configuration|Selected for Version 2|
|Git / GitHub|Version control and technical portfolio|Active|

**Separation of concerns:**

* **Infrastructure as Code:** Provision cloud resources.
* **Configuration as Code:** Configure endpoints and supporting software.
* **Detection as Code:** Version security analytics and hunting content.
* **Automation as Code:** Define repeatable response workflows.
* **Validation as Code:** Test deployed infrastructure and security capabilities.

The repository currently reserves `infrastructure/bicep/` for infrastructure definitions. A larger module structure is a future design, not an existing implementation claim.

\---

## 14\. Historical Capability Assessment

|Capability|Version 1 Assessment|Version 2 Work|
|-|-|-|
|Centralized logging|Implemented|Reconstruct and test|
|Endpoint monitoring|Implemented|Reconstruct and test|
|Alerting and detection|Implemented|Export, version, and validate|
|SOAR-lite|Implemented at prototype level|Rebuild workflows|
|Dashboards and reports|Historical implementation|Recover artifacts|
|IaC|Prototype work|Modularize and automate|
|IAM hardening|Historical work|Verify exact controls|
|Backup and recovery|Historically marked complete|Recover configuration and test evidence|
|EDR|Historical milestone|Distinguish AMA telemetry from true EDR|
|Threat hunting|Foundational capability|Version queries and tests|
|Forensic readiness|Incomplete|Design and implement|
|Vulnerability scanning|Incomplete|Design and implement|
|Compliance mapping|Incomplete|Design and implement|
|Cloud cost security analysis|Incomplete|Establish cost baseline|

**EDR clarification:** AMA collects telemetry; it does not replace an EDR platform. Version 2 will distinguish endpoint visibility, security detection, and response coverage, and verify any dedicated EDR integration before claiming it.

\---

## 15\. Configuration Gaps to Resolve

|Area|Missing Detail|Next Action|
|-|-|-|
|Subscription|Scope, providers, policies|Verify in Azure|
|Resource group|Current resource membership|Export inventory|
|Workspace|Region, retention, settings|Inspect workspace|
|Windows VM|Name, size, OS, networking|Inspect VM|
|Linux VM|Name, size, OS, networking|Inspect VM|
|Windows DCR|Name, XPath, streams|Export JSON|
|Linux DCR|Name, facilities, severities|Export JSON|
|AMA|Agent versions and health|Inspect extensions|
|Sentinel|Enabled settings and content|Export configuration|
|Analytics rules|Queries, thresholds, schedules|Export rules|
|Playbooks|Triggers, actions, connectors|Export Logic Apps|
|Watchlists|Names and schemas|Review Sentinel|
|Networking|VNets, NSGs, routes, flow data|Export topology|
|IAM|Roles, scopes, identities|Review access|
|Defender for Cloud|Plans and recommendations|Review settings|
|Storage / Key Vault|Existence and configuration|Verify resources|
|Recovery|Policies and restore tests|Collect evidence|
|Cost|Spend, ingestion, retention|Establish baseline|

Only sanitized evidence belongs in the public repository. Secrets, keys, tokens, sensitive addresses, and private customer data must not be committed.

\---

## 16\. Version 2 Reconstruction Checklist

### Discovery

* \[ ] Export existing Azure resource inventory.
* \[ ] Confirm names, types, regions, and dependencies.
* \[ ] Verify resource tags and ownership.
* \[ ] Preserve sanitized configuration evidence.

### Monitoring

* \[ ] Deploy workspace using IaC.
* \[ ] Recreate Windows and Linux endpoints.
* \[ ] Deploy AMA and DCRs.
* \[ ] Verify DCR associations.
* \[ ] Test each required telemetry table.
* \[ ] Define retention and ingestion-cost controls.

### Security Operations

* \[ ] Configure Sentinel reproducibly.
* \[ ] Rebuild and test analytics rules.
* \[ ] Version hunting queries.
* \[ ] Rebuild playbooks and permissions.
* \[ ] Restore dashboards and workbooks.
* \[ ] Validate alert-to-incident-to-response workflows.

### Security and Resilience

* \[ ] Audit RBAC and privileged access.
* \[ ] Validate network controls.
* \[ ] Review Defender for Cloud configuration.
* \[ ] Establish secrets management.
* \[ ] Implement evidence retention and forensic readiness.
* \[ ] Define backup and recovery testing.

### Engineering

* \[ ] Build reusable Terraform/Bicep modules.
* \[ ] Introduce Ansible configuration management.
* \[ ] Add deployment validation scripts.
* \[ ] Document rollback procedures.
* \[ ] Update architecture diagrams and inventory.

\---

## 17\. Inventory Governance and Commercial Direction

As BTH Cloud SOC evolves, this document should become a generated or automatically verified record of deployed infrastructure rather than a permanently manual spreadsheet in Markdown form.

My longer-term goals include automated resource discovery, configuration drift detection, tagging standards, change review through Git, cost attribution, deployment validation, and customer-specific resource isolation.

These are not just documentation improvements. They are necessary capabilities for reliable customer onboarding, security audits, service maintenance, and a scalable SOC-as-a-Service offering.

\---

## 18\. Related Repository Documentation

|Path|Purpose|
|-|-|
|`README.md`|Project overview and entry point|
|`docs/architecture/ARCHITECTURE.md`|System design and engineering decisions|
|`docs/architecture/RESOURCE-INVENTORY.md`|Resource and service inventory|
|`docs/implementation/`|Deployment and configuration procedures|
|`docs/validation/`|Test methods and results|
|`docs/incident-response/`|Incident response documentation|
|`detections/`|Detection engineering content|
|`infrastructure/`|Infrastructure definitions|
|`evidence/v1/`|Sanitized historical evidence|
|`roadmap/`|Planned capability development|
|`CHANGELOG.md`|Change history|

The architecture document explains **why and how** the system is designed. This inventory explains **what components exist or are planned**. Implementation documentation explains **how to deploy them**, and validation documentation establishes **whether they work**.

\---

## 19\. Engineering Lessons Learned

**Regional requirements matter.** A DCR/workspace mismatch forced me to understand resource compatibility rather than assuming all Azure services can be connected without constraints.

**Heartbeat is not complete ingestion validation.** An agent reporting as healthy does not prove that security events or Syslog are flowing correctly.

**Schemas matter.** Querying the wrong table or assuming a data source exists can make a functioning deployment look broken—or hide an incomplete configuration.

**Security products have different responsibilities.** Azure Monitor, Sentinel, Defender for Cloud, and Network Watcher are complementary, not interchangeable.

**Documentation is part of engineering.** If I cannot explain why a resource exists, what it depends on, how it is configured, and how to test it, I have not made the environment easy to maintain or reproduce.

\---

## 20\. Document Maintenance

Update this inventory whenever resources are deployed, removed, renamed, materially reconfigured, or revalidated. Each change should distinguish the *historical record* from the *currently observed state*.

|Status|Definition|
|-|-|
|Historically implemented|Previously configured according to project records|
|Validated|Supported by an observed test or preserved evidence|
|Verification required|Exact or current configuration not established|
|Planned|Intended for a future version|
|Incomplete|Does not yet satisfy defined completion criteria|
|Retired|Intentionally removed from the architecture|

**Maintained by:** Beware The Hacker (BTH)  
**Document classification:** Technical Architecture / Infrastructure Inventory  
**Current revision:** 1.0  
**Next review:** Version 2 infrastructure reconstruction

\---

## References

* [Azure Resource Manager](https://learn.microsoft.com/en-us/azure/azure-resource-manager/)
* [Azure Monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/)
* [Log Analytics Workspace](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview)
* [Azure Monitor Agent](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-overview)
* [Data Collection Rules](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-overview)
* [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/)
* [Azure Network Watcher](https://learn.microsoft.com/en-us/azure/network-watcher/)
* [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
* [Azure RBAC](https://learn.microsoft.com/en-us/azure/role-based-access-control/)
* [Azure Bicep](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/)
* [Kusto Query Language](https://learn.microsoft.com/en-us/kusto/query/)

