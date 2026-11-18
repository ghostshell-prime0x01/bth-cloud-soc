# BTH Cloud SOC — V1 Evidence Register

> \*\*Project:\*\* BTH Cloud SOC  
> \*\*Owner:\*\* Ghost Shell Prime  
> \*\*Scope:\*\* Historical Azure V1 implementation  
> \*\*Status:\*\* Evidence catalog in progress  
> \*\*Last updated:\*\* 2026-11-17

## Purpose

I built BTH Cloud SOC to demonstrate practical cloud security engineering—not just an architecture diagram. This register connects the capabilities I implemented and tested in Azure V1 to the artifacts that support those claims. It also makes clear what a screenshot proves, what it does not prove, and what I must validate again when I rebuild the environment in V2.

My original V1 Azure environment is no longer active. Entries marked **Historical — pending artifact review** describe previous testing and point to preserved screenshots; they are **not** claims of current operational coverage. I will not mark evidence **Reviewed** until I have inspected the actual artifact and recorded its visible results.

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

|ID|Capability|Artifact|Review state|Deployment state|
|-|-|-|-|-|
|BTH-V1-EV-001|GeoIP watchlist access via KQL|[GeoIP query screenshot](../../evidence/v1/threat-hunting/geoip-watchlist-query.png)|Pending artifact review|Historical V1|
|BTH-V1-EV-002|Network-flow investigation|[Malicious inbound flow screenshot](../../evidence/v1/network/malicious-inbound-flows.png)|Pending artifact review|Historical V1|

## BTH-V1-EV-001 — GeoIP watchlist query

**Capability:** Threat intelligence enrichment / watchlist querying  
**Evidence:** [`evidence/v1/threat-hunting/geoip-watchlist-query.png`](../../evidence/v1/threat-hunting/geoip-watchlist-query.png)  
**Source:** Microsoft Sentinel / Log Analytics watchlist  
**Historical validation method:** Execute the following KQL query:

```kql
\_GetWatchlist("geoip")
```

**Reported historical result:** The GeoIP watchlist returned queryable results in V1. The screenshot is preserved for review; the exact returned fields, row count, and timestamp have not yet been transcribed from the artifact.

**What this can establish after review:** The watchlist was accessible from the query context at the time captured, provided the screenshot shows successful execution and returned records.

**What it does not establish:** That the watchlist was updated automatically, that every entry was accurate, that analytics rules consumed it, or that enrichment triggered incidents.

**Review state:** Pending artifact review.  
**V2 revalidation:** Redeploy or import the watchlist; confirm schema and contents; execute the query; capture dated results; separately test any detection rules that reference the watchlist.

## BTH-V1-EV-002 — Malicious inbound network-flow analysis

**Capability:** Network visibility / investigation  
**Evidence:** [`evidence/v1/network/malicious-inbound-flows.png`](../../evidence/v1/network/malicious-inbound-flows.png)  
**Source:** Azure Network Watcher flow-log analytics; `AzureNetworkAnalytics\_CL` was used in V1 investigations.

**Reported historical result:** Network-flow records were investigated for malicious inbound activity, including allowed/denied flow classifications where available. The exact filter, time range, and result count must be confirmed from the screenshot or associated query text.

**What this can establish after review:** Visibility into the network-flow records displayed in the captured query or dashboard, including any shown classifications and traffic dispositions.

**What it does not establish:** Packet-level capture, verified attacker intent, comprehensive network coverage, automatic blocking, or that an alert/incident was generated.

**Review state:** Pending artifact review.  
**V2 revalidation:** Choose a currently supported flow-log collection approach; enable required network telemetry; verify ingestion, schema, timestamps, and flow disposition; reproduce the investigation; retain the KQL and dated results.

## Additional V1 evidence to collect

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

These are **collection targets**, not additional verified evidence entries.

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

## Next review actions

* \[ ] Open `geoip-watchlist-query.png` and record the visible query, timestamp (if shown), and returned fields.
* \[ ] Open `malicious-inbound-flows.png` and record the visible query/filter, time range (if shown), and disposition fields.
* \[ ] Update both entries from `Pending artifact review` to `Reviewed` only after inspection.
* \[ ] Cross-reference both evidence IDs in `CAPABILITY-MATRIX.md`.
* \[ ] Collect the next batch of telemetry and incident-response evidence.

\---

**Engineering principle:** Evidence should support the claim—not the other way around. V1 screenshots establish historical observations; V2 needs fresh, reproducible validation.

