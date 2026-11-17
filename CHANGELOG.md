# Changelog

All notable changes to **BTH Cloud SOC** are documented here.

This changelog tracks the evolution of my Azure-first Cloud Security Operations Center from a manually engineered proof of concept into a reproducible, automation-first security platform. It separates what I **actually implemented and validated** from what is **documented, planned, or awaiting reconstruction**. I want anyone reviewing this repository—whether a recruiter, engineer, or future customer—to understand the work without mistaking a roadmap for a deployed capability.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), with versioning used to describe project milestones rather than production software releases. Dates reflect known project milestones; I do not assign invented deployment dates.

## \[Unreleased] — Version 2: Infrastructure Reconstruction and Automation

### Planned

* Rebuild the Azure environment from version-controlled infrastructure definitions using **Bicep and/or Terraform**, rather than relying on portal-only configuration.
* Use **Ansible** for repeatable Windows/Linux configuration management where appropriate.
* Parameterize environments, resource names, regions, access controls, and deployment settings while keeping secrets out of Git.
* Recreate and validate Log Analytics, Microsoft Sentinel, Azure Monitor Agent, Data Collection Rules, endpoint telemetry, and detection content.
* Reestablish network telemetry using supported Azure network monitoring capabilities; verify current service availability and migration requirements before choosing a replacement for historical NSG flow-log workflows.
* Rebuild workbooks, analytics rules, watchlists, incident workflows, and controlled response automation.
* Introduce repeatable deployment checks, telemetry tests, detection tests, and evidence capture.
* Expand vulnerability management, forensic readiness, compliance mapping, and cloud-cost visibility from gaps into validated capabilities.
* Map key Azure components to AWS equivalents as the foundation for a future multi-cloud implementation.
* Evaluate AI-assisted triage, enrichment, and investigation as modular extensions; keep experimental AI features separate from proven SOC functionality.

### Acceptance Criteria

* A clean deployment can be reproduced from the repository with documented prerequisites and configuration.
* Windows and Linux sources demonstrably deliver expected events to the correct workspace.
* Detection tests generate traceable alerts/incidents with documented outcomes and false-positive considerations.
* Response workflows are tested with defined permissions, safety controls, and rollback procedures.
* Evidence demonstrates each claimed capability; documentation identifies any remaining limitations.
* Deployment cost, access requirements, and teardown steps are documented.

> \*\*Status:\*\* Planned. These items are not claims of completed Version 2 deployment.

## \[0.4.0] — 2026-11-16 — Validation and Incident Response Documentation

### Added

* `docs/incident-response/INCIDENT-RESPONSE.md` — documents the incident-response approach, operational workflow, and the relationship between Sentinel investigations and NIST SP 800-61 guidance.
* `docs/validation/CAPABILITY-MATRIX.md` — provides a centralized view of SOC capabilities, historical validation, outstanding gaps, and future reconstruction work.
* `CHANGELOG.md` — establishes an auditable history of project milestones, documentation, and planned engineering work.

### Documentation Notes

* Historical capabilities are not automatically treated as currently deployed services.
* A checked-off prototype capability is not equivalent to a production-ready, fully automated service.

## \[0.3.0] — 2026-11-14 — Architecture and Implementation Records

### Added

* `docs/architecture/ARCHITECTURE.md` — explains architecture, service selection, data flows, engineering tradeoffs, and Version 2 reconstruction priorities.
* `docs/architecture/RESOURCE-INVENTORY.md` — records known Azure resources and their roles, distinguishing historically observed resources from proposed infrastructure.
* `docs/implementation/V1-MANUAL-IMPLEMENTATION.md` — documents the original portal-driven implementation and the transition toward reproducible infrastructure.

### Changed

* Shifted the repository's documentation emphasis from a collection of lab artifacts toward an engineering case study that communicates **why** components were selected, **how** they interact, and **what evidence** supports the design.

## \[0.2.0] — 2026-11-13 — Repository Documentation Foundation

### Added

* `README.md` — serves as the entry point for the BTH Cloud SOC project, covering scope, architecture, validated work, and future direction.
* A documentation structure organized around architecture, implementation, incident response, and validation.

### Changed

* Established a consistent distinction between the historical **Version 1 manual proof of concept** and the proposed **Version 2 automated rebuild**.

## \[0.1.0] — 2026-11 — GitHub Repository Initialization

### Added

* Initialized the `bth-cloud-soc` GitHub repository structure.
* Established directories for:

  * `docs/architecture/`
  * `docs/implementation/`
  * `docs/incident-response/`
  * `docs/validation/`
  * `detections/azure-resources/`
  * `detections/identity/`
  * `detections/linux/`
  * `detections/network/`
  * `detections/windows/`
  * `infrastructure/bicep/`
  * `workbooks/` (project-planned artifact area)
  * `evidence/v1/`
  * `roadmap/`
* Added `.gitignore` protections for environment files, private keys, Terraform state and variable files, local Python environments, and other sensitive or generated artifacts.

### Notes

* Directory scaffolding does not imply that all corresponding detections, IaC modules, or evidence files have been committed.
* The original Azure resource group was no longer available for a direct export when the documentation/reconstruction effort began. Historical screenshots and recorded tests are therefore important sources of evidence.

## \[V1 Historical Prototype] — 2025 (Manual Azure Build)

> \*\*Historical milestone, not a tagged Git release.\*\* The following records capabilities built or tested during the original Azure portal-based SOC project. Specific resource creation dates were not consistently recorded.

### Added — Monitoring and Log Ingestion

* Provisioned a Log Analytics workspace, historically identified as `LAW-Cyber-Lab-0x`, to centralize security and operational telemetry.
* Connected Windows and Linux virtual machines through **Azure Monitor Agent (AMA)** and **Data Collection Rules (DCRs)**.
* Configured Windows Security event collection using XPath filtering and established Linux collection after resolving DCR platform-selection issues.
* Queried `Heartbeat`, `AzureActivity`, Windows security events, and Linux `Syslog` to validate telemetry and investigate activity.

### Added — Detection and Investigation

* Enabled **Microsoft Sentinel** against the Log Analytics workspace.
* Created and explored analytics rules, alerts/incidents, and manual playbook workflows.
* Used **Kusto Query Language (KQL)** for investigation, log validation, and initial threat-hunting exercises.
* Created a GeoIP watchlist and validated lookup access with `\_GetWatchlist("geoip")`.
* Built initial dashboards/workbooks for operational and executive visibility.

### Added — Network and Cloud Security

* Configured historical **Azure Network Watcher / NSG flow-log** visibility and investigated network-analytics data, including allowed and denied malicious-flow classifications in `AzureNetworkAnalytics\_CL`.
* Used **Microsoft Defender for Cloud** for cloud-security-posture baseline exploration.
* Applied initial identity/access and defense-in-depth considerations to the environment.

### Added — Response and Engineering

* Used **NIST SP 800-61** as a reference for incident-response activities in Sentinel.
* Created initial Bicep/IaC work and investigated how infrastructure automation could replace manual deployment.
* Explored recovery/backup, endpoint protection, and threat-hunting functionality at prototype level.

### Fixed / Lessons Learned

* Resolved a **Log Analytics workspace / DCR region mismatch**.
* Corrected a **diagnostic settings API-version mismatch** during deployment work.
* Corrected a **workspace resource ID/path issue**.
* Resolved a **Linux DCR visibility/configuration issue** by selecting the correct platform type.

### Known Gaps at the End of V1

* Forensic readiness was not fully implemented or validated.
* Vulnerability scanning was not fully implemented or validated.
* Formal compliance-control mapping was not fully implemented or validated.
* Cloud-cost security analysis was not fully implemented or validated.
* Manual response/playbook experimentation did not establish unattended production-grade SOAR.
* Historical validation does not establish that resources remain online today.

## Change Management Conventions

Going forward, I will maintain this file whenever a meaningful capability, deployment, detection, workflow, or documentation artifact changes.

* **Added:** New capabilities, resources, detections, documentation, or evidence.
* **Changed:** Material architecture, configuration, workflow, or documentation changes.
* **Fixed:** Resolved implementation defects and their operational impact.
* **Security:** Changes affecting access, secrets, detection coverage, or response safety.
* **Deprecated/Removed:** Components intentionally phased out, including replacements for retired Azure services.
* **Validated:** Tests supported by a reproducible procedure and evidence path.
* **Planned:** Intended work that must not be represented as deployed.

For each future release, I aim to include the version/date, what changed, why it changed, validation performed, and links to the relevant documentation, code, or sanitized evidence. Sensitive credentials, customer information, and unredacted security artifacts do not belong in this repository.

\---

**Maintainer:** Ghost Shell Prime  
**Project:** Beware The Hacker (BTH) Cloud SOC  
**Repository:** `bth-cloud-soc`  
**Current focus:** Preserve the verified Version 1 engineering record and build a reproducible Version 2 foundation.

