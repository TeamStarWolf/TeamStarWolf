# Tenable

Tenable is an exposure management vendor whose products scan for vulnerabilities, misconfigurations, and exposures across endpoints, web applications, cloud, and identity. The portfolio centers on Tenable One, an exposure management platform that aggregates findings from the individual products. Licence tier and module entitlement decide which products and data sources are in force for a given account. This page describes the products at a general level and does not describe any specific organization's deployment.

## What it is and where it fits

Tenable sits in the vulnerability management and exposure management part of a security program. It identifies weaknesses before an attacker can use them, then helps rank and track remediation. The products share a finding model built on plugins, so results from different scan types read consistently.

Tenable One is the platform layer. It pulls asset and finding data from the operational products into a shared asset inventory and exposure view. Teams use it to prioritize across many asset classes rather than one scan at a time.

The operational products include Tenable Vulnerability Management (formerly tenable.io), the Nessus scanner, Tenable Web App Scanning, Tenable Cloud Security, and Tenable Identity Exposure. Each covers a different surface, and each feeds the shared model.

## Architecture and how it works

Tenable Vulnerability Management runs as a cloud-hosted service. Data collection happens through scanners and agents that report findings back to the platform. Scanners can be cloud-hosted by Tenable or deployed as on-premises scanner appliances for internal networks.

Nessus is the scan engine. It runs the plugin checks that detect vulnerabilities, missing patches, and misconfigurations. Nessus Agents install on hosts and scan locally, which suits laptops and systems that are not always reachable over the network.

Tenable Web App Scanning performs dynamic testing of running web applications. Tenable Cloud Security reads cloud provider configuration and workloads. Tenable Identity Exposure analyzes Active Directory and Entra ID for weaknesses in identity infrastructure.

Findings from these products normalize into assets and vulnerability instances. Each asset carries attributes such as network address, operating system, and tags. The platform tracks the state of each finding over time.

## Key capabilities

Detections are expressed as plugins. Each plugin checks for one condition and belongs to a plugin family, such as a product vendor or a check category. A scan result is a set of plugin outputs tied to specific assets.

The Vulnerability Priority Rating (VPR) scores how likely a vulnerability is to be exploited and how severe the impact would be. VPR draws on threat and exploit data and updates as that data changes. It gives a ranking that differs from the static base severity of a CVE.

Asset criticality lets teams weight findings by how important the affected asset is. A high VPR on a business-critical asset rises above the same score on a low-value host. This pairing drives remediation order.

Authenticated scanning produces deeper results than unauthenticated scanning. With valid credentials, Nessus can read installed packages, patch levels, and local configuration. Agents provide similar depth without needing network credentials at scan time.

The platform tracks finding state across rescans. A vulnerability that no longer appears after remediation is marked `fixed`. A vulnerability that reappears is marked reopened, which flags remediation that did not hold.

## Deployment and operations

A common pattern mixes scanner appliances for data center and network ranges with agents for roaming endpoints. Web App Scanning targets application URLs. Cloud Security connects to cloud accounts through provider roles.

Scan schedules balance coverage against load on the target environment. Authenticated scans need managed credentials, which raises the operational importance of credential handling. Scan windows and throttling settings keep scanning from disrupting production systems.

Operations teams maintain scan policies, credential sets, and asset tags. Tags drive dynamic asset groups, which in turn drive scan scope and reporting. Keeping tags accurate keeps prioritization accurate.

## Integrations and data flow

Findings flow out to downstream systems. Tenable integrates with ServiceNow so that vulnerabilities can open and update records in ServiceNow Vulnerability Response, where remediation is assigned and tracked. The integration keeps ticket state aligned with scan state.

SIEM integration sends vulnerability and asset data to log analytics platforms. This lets detection teams correlate exposure data with alerts and telemetry. Export APIs and connectors move bulk finding data for reporting and data warehousing.

The direction of flow is Tenable as the source of vulnerability truth, with ServiceNow and the SIEM as consumers. Keeping asset identity consistent across these systems is what makes the join reliable.

## Hardening and secure use

Scan credentials are a high-value secret. Store them in Tenable's credential management or an integrated vault rather than embedding them in scan policies as plain values. Avoid hard-coded credentials in automation that drives the API (CWE-798). Rotate credentials on a schedule and scope them to the least access a scan needs.

Role-based access control limits who can view findings, run scans, and manage configuration. Grant users the narrowest role that fits their job. Separate scan operators from administrators who manage credentials and integrations.

API keys authenticate programmatic access. Treat them as secrets, store them outside source code, and rotate them. Scope keys to specific users and review them when staff change roles. A leaked key with broad scope exposes the whole tenant.

Tenant configuration matters for multi-team use. Use access groups and tags to keep teams scoped to their own assets. Review integration connectors, since each one is a path that carries finding data outside the platform.

## Where it fits in the program

Tenable supplies the detection and prioritization layer of vulnerability management. It answers what is vulnerable, how urgent each finding is, and whether remediation held on rescan. The VPR and asset criticality pairing turns a long finding list into an ordered work queue.

In a mature program, Tenable findings open tickets in ServiceNow Vulnerability Response and feed metrics such as mean time to remediate. The scan state machine, with its fixed and reopened tracking, is what lets those metrics reflect real closure rather than ticket closure alone.

## Resources

- Tenable Vulnerability Management documentation
- Nessus User Guide
- Tenable One documentation
- Tenable Web App Scanning documentation
- Tenable Cloud Security documentation
- Tenable Identity Exposure documentation

## Related pages

- /platforms/README.md
- /SCANNER_PLATFORMS_REFERENCE.md
- /VULNERABILITY_MANAGEMENT_REFERENCE.md
- /platforms/qualys.md
- /platforms/rapid7-insightvm.md
- /platforms/servicenow-vr.md
