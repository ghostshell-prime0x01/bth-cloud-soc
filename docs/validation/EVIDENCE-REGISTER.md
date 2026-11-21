# BTH Cloud SOC — V1 Evidence Register

> \*\*Project:\*\* BTH Cloud SOC  
> \*\*Owner:\*\* Ghost Shell Prime  
> \*\*Scope:\*\* Historical Azure V1 implementation  
> \*\*Status:\*\* Four historical screenshot artifacts reviewed; additional validation deferred to V2  
> \*\*Last updated:\*\* 2026-11-21

## Purpose

I built BTH Cloud SOC to demonstrate practical cloud security engineering—not just an architecture diagram. This register connects the capabilities I implemented and tested in Azure V1 to the artifacts that support those claims. It also makes clear what a screenshot proves, what it does not prove, and what I must validate again when I rebuild the environment in V2.

My original V1 Azure environment is no longer active. The four preserved screenshots have now been reviewed individually. **Reviewed** means the artifact was inspected and its visible content recorded; it does not mean the underlying detection pipeline or the current environment has been independently revalidated. Historical V1 observations are not claims of current operational coverage.

## Evidence handling standard

* **Evidence ID:** Stable identifier in the format `BTH-V1-EV-###`.
* **Artifact:** Relative path from the repository root; preserve meaningful filenames.
* **Source:** Azure service, log table, query, alert, or workflow that generated the result.
* **Validation:** Specific action performed and the observable outcome.
* **Limits:** Explicitly state what the artifact cannot establish.
* **Review state:** `Pending artifact review`, `Reviewed`, or `Needs replacement`.
* **Deployment state:** Historical V1 versus current V2 validation must remain separate.
* **Privacy:** Review artifacts for credentials, tokens, personal data, tenant/subscription identifiers, and sensitive IPs before publishing. Keep unredacted originals private when appropriate.

## Evidence index

|ID|Capability directly supported|Artifact|Review state|Deployment state|
|-|-|-|-|-|
|BTH-V1-EV-001|GeoIP watchlist query and returned records|[GeoIP query screenshot](../../evidence/v1/threat-hunting/geoip-watchlist-query.png)|Reviewed|Historical V1|
|BTH-V1-EV-002|Sentinel network-oriented geographic workbook visualization|[Network workbook screenshot](../../evidence/v1/network/malicious-inbound-flows.png)|Reviewed|Historical V1|
|BTH-V1-EV-003|Sentinel Windows RDP-oriented geographic workbook visualization|[Windows workbook screenshot](../../evidence/v1/dashboards/windows-security-monitoring.png)|Reviewed|Historical V1|
|BTH-V1-EV-004|Sentinel Linux SSH-oriented geographic workbook visualization|[Linux workbook screenshot](../../evidence/v1/dashboards/linux-security-monitoring.png)|Reviewed|Historical V1|

**Artifact path note:** Paths reflect the intended repository locations reported during evidence organization. Verify filename case and committed GitHub links after publication.

## BTH-V1-EV-001 — GeoIP watchlist query

**Capability:** Watchlist retrieval through KQL; historical threat-hunting support  
**Evidence:** [`evidence/v1/threat-hunting/geoip-watchlist-query.png`](../../evidence/v1/threat-hunting/geoip-watchlist-query.png)  
**Source:** Azure Log Analytics workspace `LAW-Cyber-Lab-0x`  
**Query visible in screenshot:**

```kql
\_GetWatchlist("geoip")
```

**Observed result:** The Results pane contains populated watchlist rows, with visible columns including `SearchKey`, `cityname`, `countryname`, `\_DTItemId`, and a last-updated UTC field. Seven rows are visible, with a display indicator of `1 - 7 of 1000`; the latter is not proof of total watchlist size. Example country values include Iran, Russia, Netherlands, Italy, Poland, and France. The interface shows an execution duration of approximately 0.913 seconds. The displayed record-update timestamp is April 10, 2025; this is **not** a verified screenshot capture or query execution date.

**What this validates:** The `geoip` watchlist was accessible and returned structured records in the historical workspace.

**Limitations:** The screenshot does not prove that the records were malicious, that the watchlist was refreshed automatically, that an analytics rule used it, or that any incident was generated.

**Review state:** Reviewed — watchlist retrieval validated at screenshot level.  
**V2 revalidation:** Import or deploy the watchlist, capture the query and schema with an explicit UTC test timestamp, validate its provenance and refresh process, and separately test rules that join against it.

## BTH-V1-EV-002 — Network-oriented geographic workbook

**Capability:** Sentinel Workbook visualization for network-security investigation  
**Evidence:** [`evidence/v1/network/malicious-inbound-flows.png`](../../evidence/v1/network/malicious-inbound-flows.png)  
**Source:** Microsoft Sentinel > Workbooks; workbook title `nsg-malicious-allowed-in`, workspace `law-cyber-lab-0x`.

**Observed result:** A rendered world map displays geographic markers of varying sizes and colors, together with location summary values. Visible examples include Nancy (France) 537, Other 205, Irwin (United States) 192, Boonton (United States) 161, and Lorinci (Hungary) 106. The screenshot does not identify the metric unit or the workbook query.

**What this validates:** A historical Sentinel Workbook was configured and rendered a populated geographic visualization with location summaries.

**Historical context:** Earlier implementation notes report investigations using `AzureNetworkAnalytics\_CL` and malicious allowed/denied flow classifications. Those notes are contextual claims, **not** independently demonstrated by this screenshot.

**Limitations:** The underlying KQL, data source, flow direction, allow/deny disposition, threat classification, time range, and alert/incident generation are not visible. The title alone does not prove the plotted traffic was malicious or allowed inbound.

**Review state:** Reviewed — workbook visualization validated; network-flow classification not independently verified.  
**V2 revalidation:** Preserve the workbook definition and KQL, select a supported network telemetry source, verify source schema and flow dispositions, run controlled traffic tests, and capture the resulting query output and visualization with UTC timestamps.

## BTH-V1-EV-003 — Windows RDP authentication-oriented workbook

**Capability:** Windows authentication monitoring visualization  
**Evidence:** [`evidence/v1/dashboards/windows-security-monitoring.png`](../../evidence/v1/dashboards/windows-security-monitoring.png)  
**Source:** Microsoft Sentinel > Workbooks; workbook title `windows-rdp-auth-fail`, workspace `law-cyber-lab-0x`.

**Observed result:** A populated global map with location summary values, including Düsseldorf (Germany) 240, Lac-du-Cerf (Canada) 225, another Düsseldorf entry 225, France 159, and Chantilly (France) 89. Repeated labels are transcribed as shown, without assuming they represent distinct entities. The metric unit and time range are not visible.

**What this validates:** A historical Sentinel Workbook intended for Windows/RDP authentication monitoring rendered a populated geographic visualization.

**Limitations:** No underlying KQL, `SecurityEvent` table results, Windows Event ID 4625, RDP logon-type filtering, or alert/incident result is visible. Failed RDP logons and brute-force detection are therefore **not** independently established by this image.

**Review state:** Reviewed — workbook visualization validated; Windows event ingestion and RDP filtering not independently verified.  
**V2 revalidation:** Generate authorized failed RDP authentication attempts on a test Windows host, verify AMA/DCR ingestion and event fields, version-control the KQL, and confirm workbook aggregations match raw results.

## BTH-V1-EV-004 — Linux SSH authentication-oriented workbook

**Capability:** Linux authentication monitoring visualization  
**Evidence:** [`evidence/v1/dashboards/linux-security-monitoring.png`](../../evidence/v1/dashboards/linux-security-monitoring.png)  
**Source:** Microsoft Sentinel > Workbooks; workbook title `linux-ssh-auth-fail`, workspace `law-cyber-lab-0x`.

**Observed result:** A populated world map with location summary values. Visible examples include Glendora (United States) 7.63k, Central (Hong Kong) 249, Martin (United States) 106, Manaus (Brazil) 81, and Other 75. The prominent Glendora value is a displayed aggregate, **not** proof of 7,630 failed SSH attempts; the measurement unit and aggregation query are not shown.

**What this validates:** A historical Sentinel Workbook intended for Linux/SSH authentication monitoring rendered a populated geographic visualization.

**Limitations:** The screenshot does not independently verify `Syslog` ingestion, `sshd` message filtering, SSH authentication failures, brute-force detection, or Sentinel incidents.

**Review state:** Reviewed — workbook visualization validated; Linux SSH detection logic not independently verified.  
**V2 revalidation:** Generate safe SSH failures on an authorized Linux test VM, validate Syslog collection through AMA/DCR, capture raw events and the workbook query, and reconcile displayed counts with query output.

## Historical evidence gaps and V2 collection targets

|Area|Candidate artifact|Intended validation|
|-|-|-|
|Telemetry|AMA and DCR configuration; Heartbeat and Windows/Linux log queries|Agent connectivity, collection rules, and ingestion|
|Detection|Sentinel analytics rule configuration and test results|Rule logic and observed alert behavior|
|Incident response|Sentinel incident screenshots and investigation notes|Incident creation, triage, and response workflow|
|Automation|Playbook configuration and run history|Workflow execution, not merely existence|
|Cloud activity|`AzureActivity` query results|Control-plane event visibility|
|Dashboards|Azure Workbook screenshots|Visualization of ingested security data|
|Security posture|Defender for Cloud findings|Observed posture assessment at capture time|
|Identity|RBAC assignments and access tests, appropriately redacted|Scope and effectiveness of access controls|

These are **V2 collection targets**, not additional preserved V1 screenshots or verified evidence entries. The historical screenshot review is complete; do not imply these artifacts still exist or must be recovered.

## How this connects to the capability matrix

For each capability in [`CAPABILITY-MATRIX.md`](CAPABILITY-MATRIX.md):

1. Link to one or more evidence IDs in this register.
2. Distinguish implemented, historically tested, and currently operational status.
3. Record missing proof instead of upgrading a claim without evidence.
4. Add a V2 validation test and capture fresh results after reconstruction.

## Evidence intake workflow

1. Locate the original artifact and preserve a private copy if needed.
2. Check for sensitive data and publish only a safe version.
3. Place it in the appropriate `evidence/v1/` category.
4. Add a unique evidence ID and relative Markdown link here.
5. Inspect the actual image or query output and record only visible results.
6. Document limitations and any missing query, timestamp, or context.
7. Update the capability matrix with the evidence ID.
8. Commit the register and evidence together using a descriptive commit message.

## Review completion and next actions

* \[x] Review GeoIP query screenshot and transcribe visible results and limitations.
* \[x] Review network-oriented workbook screenshot without assuming unseen KQL or dispositions.
* \[x] Review Windows RDP-oriented workbook screenshot.
* \[x] Review Linux SSH-oriented workbook screenshot.
* \[x] Assign stable evidence IDs and cross-reference the capability matrix.
* \[ ] Verify all four evidence links resolve in the published GitHub repository.
* \[ ] Capture fresh source-query, event-ingestion, detection, and incident evidence during V2 reconstruction.

\---

**Engineering principle:** Evidence should support the claim—not the other way around. V1 screenshots establish historical observations; V2 needs fresh, reproducible validation.


## WIN-001 v1.1 — Offline Regression Evidence

**Detection:** WIN-001 — Repeated Windows Failed Logons

**Version:** 1.1 (candidate)

**Validation environment:** Local Debian / Python 3

**Evidence artifact:**
`evidence/v2/detections/windows/WIN-001-full-regression.txt`

**Validation results:**
- Baseline detection tests: 3 PASS
- Extended baseline tests: 5 PASS
- Sliding-window model tests: 6 PASS
- Deduplication model tests: 5 PASS
- Total: 19 PASS
- Python exit status: 0

**Validated behavior:**
- Detection threshold enforcement in local models
- Separation by host, account, and source IP
- Boundary-spanning authentication failures
- Exclusion of successful authentication events
- Latest qualifying window selection per entity

**Known limitations:**
- Python tests do not execute KQL.
- Final KQL syntax and behavior remain unverified in Azure.
- Deduplication may collapse separate bursts from the same entity.
- Duplicate alerts across Sentinel executions remain possible.
- Empty source IP handling requires a documented policy.
- Query performance has not been measured.

**Validation status:** Offline Python model tests passed.
Azure KQL execution and Sentinel deployment pending.


## WIN-002 — Successful Logon After Repeated Failures

**Status:** Offline Python validation passed;
KQL candidate not executed.

**Evidence directory:**
`evidence/v2/detections/windows/`

### Evidence Artifacts

- `WIN-002-offline-tests.txt`
- `WIN-002-extended-tests.txt`
- `WIN-002-identity-tests.txt`

### Validation Summary

- Initial tests: 10 PASS
- Extended tests: 6 PASS
- Event identity test: 1 PASS
- Total: 17 PASS
- Exit status: 0 for each suite

### Validation Scope

The evidence demonstrates the behavior of the Python
reference model against synthetic authentication events.

It does not demonstrate successful KQL execution,
production telemetry ingestion, or Sentinel alert generation.

### Deferred Validation

- Verify SecurityEvent schema and field mappings.
- Execute and troubleshoot the KQL candidate.
- Validate correlation against controlled Windows events.
- Assess duplicate alerts and ingestion latency.
- Configure Sentinel analytics rule.
- Capture live detection and incident evidence.
