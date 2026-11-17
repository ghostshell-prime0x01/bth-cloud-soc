# BTH Cloud SOC — Capability Matrix

> \*\*Project:\*\* Beware The Hacker (BTH) Cloud SOC  
> \*\*Document:\*\* `docs/validation/CAPABILITY-MATRIX.md`  
> \*\*Scope:\*\* Version 1 historical validation and Version 2 reconstruction  
> \*\*Status:\*\* Historical capability assessment; current deployment requires revalidation  
> \*\*Last reviewed:\*\* 2026-11-16

## Purpose

I built the first version of BTH Cloud SOC to prove that I could connect security telemetry, detection engineering, investigation, and response into a functioning Azure-based SOC workflow. This matrix separates what I actually implemented and tested from what remains incomplete or needs to be rebuilt.

A checked capability does **not** mean I am claiming a production-ready managed security service. Version 1 was a hands-on prototype built primarily through the Azure portal. The original resource group is no longer available, so historical validation and current operational status are different things. Version 2 will reproduce the validated capabilities with infrastructure as code, configuration automation, repeatable tests, and better evidence management.

## Status and evidence conventions

|Label|Meaning|
|-|-|
|**Historically validated**|I exercised the capability in V1 and observed relevant output; not a claim that it is live today.|
|**Implemented / partial**|I configured or explored the capability, but available evidence does not establish end-to-end or comprehensive validation.|
|**Planned / gap**|I have not established sufficient implementation or validation evidence.|
|**Revalidation required**|The V1 environment is unavailable; V2 must demonstrate the capability again.|

**Evidence standard:** An evidence reference is only a pointer to a type of artifact or a previously discussed screenshot. It is not proof that a file is currently committed to the repository. Each V2 test should record the test date, deployment/commit identifier, configuration, query or command, expected outcome, observed outcome, and sanitized supporting artifact.

## Executive capability matrix

|#|Capability|V1 assessment|Historical basis|V2 acceptance requirement|
|-|-|-|-|-|
|01|Log collection / SIEM|**Historically validated**|AMA, DCRs, LAW ingestion, Windows/Linux telemetry, Heartbeat|Deploy collectors via code; verify fresh events from each source|
|02|Alerting and monitoring|**Historically validated**|Sentinel analytics and incidents; Azure monitoring|Trigger a known event and verify alert/incident creation|
|03|Threat detection|**Historically validated**|KQL investigation, Sentinel rules, network-flow analysis|Version-controlled detections with reproducible test cases|
|04|Automated response / SOAR-lite|**Implemented / partial**|Sentinel playbooks created and manually exercised; automated end-to-end triggering not fully evidenced|Demonstrate approved incident-to-playbook execution and audit trail|
|05|Dashboards and reporting|**Historically validated**|Azure Workbooks / executive views|Deploy workbook definitions and validate live data visualizations|
|06|Infrastructure as code|**Implemented / partial**|Initial Bicep/DCR work; V1 mainly portal-built|Rebuild core stack from reviewed Bicep/Terraform with reproducible results|
|07|Zero Trust / IAM hardening|**Implemented / partial**|Azure identity/access and security-baseline work|Verify least privilege, managed identities, access boundaries, and audit logs|
|08|Disaster recovery / backups|**Implemented / partial**|V1 checklist marked complete; recoverability proof not retained in current record|Execute and document a recovery test, RPO/RTO assumptions, and restoration evidence|
|09|Endpoint detection and response|**Implemented / partial**|Defender-related baseline and endpoint monitoring work; EDR incident lifecycle not fully evidenced|Verify endpoint onboarding, alert generation, triage, and containment permissions|
|10|Threat hunting fundamentals|**Historically validated**|KQL hunts across security, activity, system, and network telemetry|Run documented hypotheses and retain query/output evidence|
|11|Forensics readiness|**Planned / gap**|No complete collection, retention, integrity, and chain-of-custody workflow established|Demonstrate evidence preservation and documented handling procedure|
|12|Vulnerability scanning|**Planned / gap**|No validated scanning-to-remediation lifecycle established|Scan test assets, triage findings, and verify remediation|
|13|Compliance mapping|**Planned / gap**|Frameworks studied; control-to-evidence mapping not complete|Map controls to owners, implementations, tests, and artifacts|
|14|Cloud cost security analysis|**Planned / gap**|No validated cost governance or security-cost reporting workflow|Establish budgets, ingestion visibility, cost alerts, and review evidence|

**Interpretation:** The original V1 checklist marked capabilities 01–10 complete and 11–14 open. This document deliberately uses a stricter evidence-based classification: a completed learning milestone is not automatically a fully verified, deployable, production-grade capability.

## Detailed validation register

### 01 — Log collection and SIEM

**Architecture:** Windows and Linux VMs → Azure Monitor Agent (AMA) → platform-appropriate Data Collection Rules (DCRs) → Log Analytics Workspace (`LAW-Cyber-Lab-0x`) → Microsoft Sentinel.

**What I validated:** Agent heartbeat, Windows/Linux collection configuration, ingestion into Log Analytics, and KQL visibility. The Windows DCR included Security event XPath filtering. The Linux DCR required the correct platform selection before it appeared as expected.

**V2 test:** Deploy a Windows and Linux test host; confirm AMA association; generate known Windows security and Linux syslog events; verify expected records, timestamps, host identity, and ingestion latency. Capture DCR resource IDs and sanitized query results.

**Caveat:** A successful Heartbeat alone does not prove that every desired event stream is being collected.

### 02 — Alerting and monitoring

**What I validated:** Sentinel analytics rules, incident views, and monitoring data from the workspace. I also used Azure Activity events to investigate VM start/stop activity.

**V2 test:** Create a safe synthetic event matching a documented analytic rule, record alert and incident IDs, confirm severity/entity mapping, and measure event-to-alert delay. Check false-positive handling and suppression logic.

### 03 — Threat detection

**What I validated:** KQL-based analysis across `AzureActivity`, `Heartbeat`, Windows security telemetry, `Syslog`, and network analytics data. I inspected allowed and denied malicious-flow classifications in `AzureNetworkAnalytics\_CL` and used a GeoIP watchlist with `\_GetWatchlist("geoip")`.

**V2 test:** Keep each analytic in `/detections/` with its purpose, ATT\&CK mapping where justified, data dependencies, query, test procedure, expected result, tuning notes, and rollback guidance. Recheck source table/schema availability before deploying queries.

**Caveat:** Detection coverage depends on data source configuration, data quality, licensing, and the tested attack behavior. A single alert does not prove broad ATT\&CK coverage.

### 04 — SOAR-lite / incident response automation

**What I implemented:** Microsoft Sentinel playbooks and hands-on incident response workflows, using NIST SP 800-61 as a procedural reference.

**Evidence limitation:** I created playbooks manually, but the retained project history does not establish a fully automated trigger-to-action-to-verification sequence for each playbook. This is therefore partial, not a blanket claim of autonomous response.

**V2 test:** Start with a non-destructive notification/enrichment playbook. Validate incident trigger, permissions, run history, error handling, analyst approval gates, and incident updates. Keep disruptive containment actions approval-based until tested.

### 05 — Dashboards and reporting

**What I validated:** Azure Workbooks and executive-facing visualizations built on collected telemetry.

**V2 test:** Store workbook definitions in source control; deploy to the intended workspace; verify time ranges, filters, queries, data freshness, and role-based access. Document what each metric actually measures.

### 06 — Infrastructure as code

**What I implemented:** Initial Bicep work, including a Windows DCR definition. Most V1 resources were configured manually through the portal.

**V2 test:** Recreate resource groups, LAW, DCRs, Sentinel configuration, and supporting security resources through reviewed IaC. Validate idempotence, parameterization, region compatibility, secrets handling, and teardown. Use Ansible where guest operating system configuration is appropriate.

**Caveat:** IaC is a Version 2 delivery objective; V1 was not an entirely code-provisioned environment.

### 07 — Zero Trust and IAM

**What I implemented:** Identity/access configuration and cloud security posture work, including Defender for Cloud baseline exploration.

**V2 test:** Inventory principals and role assignments, minimize privileges, use managed identities where possible, protect secrets, review network exposure, and verify audit logging. Capture explicit policy and access-test evidence before marking this fully validated.

### 08 — Disaster recovery and backups

**Historical record:** The V1 milestone checklist marked DR/backups complete, but the currently available documentation does not establish an independently repeatable restoration test.

**V2 test:** Identify recoverable assets (configuration, detection rules, workbooks, evidence, and applicable data); define retention and recovery objectives; restore a representative resource or configuration; document elapsed time and outcome.

### 09 — Endpoint detection and response

**Historical record:** EDR was marked complete in the V1 checklist, alongside Defender-related security posture work. The available record does not demonstrate full endpoint alert-to-containment validation.

**V2 test:** Record licensing and product boundaries; onboard a test endpoint; generate a safe test detection; verify investigation fields, permissions, response workflow, and retained audit trail. Distinguish Defender for Cloud posture assessment from dedicated endpoint EDR functionality.

### 10 — Threat hunting

**What I validated:** Hands-on KQL exploration of host, Azure activity, and network signals; GeoIP watchlist lookups; and hypotheses around suspicious traffic and DNS-related anomalies.

**V2 test:** Create a repeatable hunt notebook/template: hypothesis → required data → KQL → findings → disposition → detection engineering opportunity. Preserve negative findings as well as confirmed results.

### 11 — Forensics readiness

**Gap:** No comprehensive acquisition and preservation process is documented as validated.

**V2 test:** Define evidence sources, retention, UTC time normalization, access controls, collection methods, integrity hashes, chain of custody, and escalation criteria. Test on an authorized lab incident.

### 12 — Vulnerability scanning

**Gap:** No end-to-end vulnerability identification, prioritization, remediation, and rescan workflow is documented as validated.

**V2 test:** Run an authorized scan against lab assets, assess severity and exploitability, create remediation tickets, rescan, and capture before/after results. Do not confuse Defender for Cloud recommendations with proof that a full vulnerability-management process exists.

### 13 — Compliance mapping

**Gap:** NIST, CIS, ISO 27001, and SOC reporting concepts inform the architecture, but a complete control-to-evidence register has not been validated.

**V2 test:** Start with a defined baseline (for example, selected NIST CSF 2.0 outcomes or CIS Controls). For each control, identify scope, implementation, evidence, testing cadence, gaps, and responsible role. Do not describe the lab as SOC 2 certified or compliant.

### 14 — Cloud cost security analysis

**Gap:** No repeatable process for SOC ingestion cost, budget thresholds, and security-related cost anomalies is documented as validated.

**V2 test:** Tag resources, establish Azure budgets and alerts, estimate LAW ingestion/retention and Sentinel costs, measure cost per data source, and review unusual spending. Validate against current Azure pricing and actual usage before commercial quoting.

## Evidence index and traceability

|Evidence / location|Supports|Verification note|
|-|-|-|
|Historical screenshot **84** (GeoIP watchlist query)|Watchlist lookup / hunting|Confirm image and metadata are committed under `evidence/v1/` before linking|
|Historical screenshot **119** (malicious inbound flow analysis)|Network visibility / detection|Confirm image and underlying query/context before linking|
|`evidence/v1/`|Historical V1 artifacts|Populate with sanitized screenshots and explanatory captions|
|`detections/windows/`, `detections/linux/`, `detections/network/`, `detections/identity/`, `detections/azure-resources/`|Version-controlled detection content|Folders do not prove detection coverage until rules and tests are committed|
|`docs/architecture/ARCHITECTURE.md`|Design and component relationships|Architectural rationale, not runtime proof|
|`docs/architecture/RESOURCE-INVENTORY.md`|Resource inventory|Reconcile historical names with V2 deployment output|
|`docs/implementation/V1-MANUAL-IMPLEMENTATION.md`|Historical build steps|Reconstruct and validate rather than assuming current deployment|
|`docs/incident-response/INCIDENT-RESPONSE.md`|Response process|Procedures require exercise records to demonstrate readiness|

**Evidence handling:** Redact tenant IDs where unnecessary, subscription identifiers, IP addresses tied to real environments, usernames, tokens, secrets, and sensitive incident details. Preserve the original context privately when needed, and never commit credentials or unrestricted evidence dumps.

## Version 2 validation gates

|Gate|Exit criteria|
|-|-|
|**G1 — Deploy**|IaC deploys expected resources without undocumented manual fixes; parameters and versions are recorded|
|**G2 — Ingest**|Fresh test events from Windows, Linux, Azure control plane, and selected network sources appear in the expected tables|
|**G3 — Detect**|At least one safe positive and one negative test per priority detection, with documented expected/observed outcomes|
|**G4 — Investigate**|Analyst can pivot from incident to relevant host, user, activity, and network evidence|
|**G5 — Respond**|Approved playbook executes safely, records run history, and supports failure/rollback handling|
|**G6 — Govern**|IAM, retention, evidence integrity, cost controls, and recovery assumptions have documented checks|
|**G7 — Reproduce**|A clean rebuild and repeat validation produce consistent results; artifacts are committed and cross-linked|

No gate is considered passed until dated evidence exists. Where a source is unavailable or a feature is out of scope, record **Not tested** or **Not applicable**, with the reason, instead of treating silence as success.

## Validation record template

Copy this template into a per-test Markdown file under `docs/validation/` or link to a corresponding sanitized evidence artifact.

```markdown
### Test ID: BTH-V2-XXX
- Capability:
- Date (UTC):
- Environment / subscription alias:
- Git commit / deployment version:
- Test owner:
- Prerequisites and data source:
- Test action / query:
- Expected result:
- Observed result:
- Status: PASS / FAIL / BLOCKED / NOT TESTED
- Evidence path:
- Limitations / false positives:
- Remediation or follow-up:
```

## Current engineering priorities

1. Rebuild the telemetry foundation with IaC and validate AMA/DCR-to-LAW ingestion.
2. Reintroduce Sentinel detections and document reproducible positive/negative tests.
3. Validate incident creation, triage, and an approval-aware SOAR-lite playbook.
4. Restore workbook visibility and preserve evidence with clear test metadata.
5. Close the four open capability gaps: forensics, vulnerability management, compliance mapping, and cloud cost security analysis.
6. Strengthen the partial areas: IAM, DR, EDR, and fully reproducible IaC.

## Final assessment

Version 1 established a working foundation for an Azure-centered SOC: I collected telemetry, queried it with KQL, investigated network and cloud activity, configured Sentinel analytics and incident workflows, and built reporting views. It also exposed real engineering issues—DCR platform selection, region alignment, API versions, and resource identifiers—that I had to troubleshoot rather than simply follow a diagram.

Version 2 is where I turn those manual lessons into a reproducible engineering product. The standard is straightforward: **if I claim a capability, I should be able to show how it was configured, how I tested it, what the result was, and what limitations remain.** That is the difference between a feature checklist and an auditable SOC capability.

\---

**Related documents:** [`ARCHITECTURE.md`](../architecture/ARCHITECTURE.md) · [`RESOURCE-INVENTORY.md`](../architecture/RESOURCE-INVENTORY.md) · [`V1-MANUAL-IMPLEMENTATION.md`](../implementation/V1-MANUAL-IMPLEMENTATION.md) · [`INCIDENT-RESPONSE.md`](../incident-response/INCIDENT-RESPONSE.md)

