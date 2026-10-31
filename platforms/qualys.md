# Qualys

Qualys is a cloud-based vulnerability management and compliance vendor. Its products run on the Qualys Cloud Platform and share a common asset inventory and data model. The flagship product is VMDR, which covers vulnerability management, detection, and response in one workflow. Licence tier and module entitlement decide which apps and data sources are in force; this page does not describe any specific organization's deployment.

## What it is and where it fits

Qualys sits in the vulnerability management, patch, and compliance part of a security program. It finds vulnerabilities and misconfigurations across hosts, web applications, and cloud, then supports the response that follows. The shared platform lets several apps read one asset inventory.

VMDR is the core vulnerability workflow. It detects vulnerabilities, scores them, and connects detection to patching so that remediation stays in the same tool. Other apps, such as Policy Compliance and Web Application Scanning, extend the platform to adjacent needs.

The platform fits alongside ticketing and SIEM systems. Qualys is the source of vulnerability and compliance findings, and those findings flow out to where remediation and correlation happen.

## Architecture and how it works

The Qualys Cloud Platform is the central hosted service. It stores the asset inventory, runs the scoring, and hosts the apps. Data reaches the platform through cloud agents and scanner appliances.

Cloud agents install on hosts and collect data locally, then report to the platform. Agents suit endpoints that move between networks and systems that are not always reachable for network scanning. They provide continuous data rather than point-in-time scans.

Scanner appliances perform network-based scanning of IP ranges. They run as virtual or physical appliances inside the environment and reach assets that do not run an agent. Authenticated scans use managed credentials to read deeper host state.

VMDR, Patch Management, Policy Compliance, and Web Application Scanning are apps on this platform. Each reads the shared inventory and adds its own detections and workflows. Because the inventory is shared, an asset appears once across the apps.

## Key capabilities

Detections are identified by QIDs. A QID is a Qualys identifier for a specific vulnerability or check. Scan results list QIDs against the assets where they were found, which gives a stable reference across scans and reports.

TruRisk is the risk scoring model. It combines vulnerability severity, threat and exploit intelligence, and asset context into a risk score. TruRisk ranks findings by real risk rather than base severity alone, which drives remediation order.

VMDR connects detection to Patch Management. From a prioritized finding, teams can deploy the patch that addresses it without leaving the workflow. This keeps the detect-and-fix loop inside one platform.

Policy Compliance checks configuration against policies and benchmarks. Web Application Scanning tests running web applications for vulnerabilities. Cloud agents and scanner appliances feed all of these with current asset data.

Finding state tracks across scans. A QID that no longer appears after remediation is marked fixed, and one that reappears is flagged. This supports metrics on whether remediation actually closed the exposure.

## Deployment and operations

A common pattern uses cloud agents for endpoints and servers, with scanner appliances for network ranges and devices that cannot run an agent. Web Application Scanning targets application URLs. Cloud connectors read cloud provider inventory.

Authenticated network scans need managed credentials, which makes credential handling an operational priority. Scan schedules and throttling protect production systems from load. Agent configuration profiles control how often agents collect and report.

Operations teams maintain asset tags, scan configurations, and credential records. Tags drive dynamic asset groups, scan scope, and reporting. Accurate tagging keeps TruRisk prioritization aligned with business context.

## Integrations and data flow

Findings flow to downstream systems for remediation and correlation. Qualys integrates with ServiceNow so vulnerabilities open and update records in ServiceNow Vulnerability Response, where work is assigned and tracked. The integration syncs ticket state with finding state.

SIEM integration sends vulnerability and asset data to log analytics platforms. Detection teams correlate exposure with alerts and telemetry. Export APIs move bulk finding data for reporting and data warehousing.

Qualys is the source of vulnerability and compliance truth, and ServiceNow and the SIEM consume it. Consistent asset identity across the systems is what keeps the join reliable.

## Hardening and secure use

Scan credentials are a high-value secret. Store them in the platform's authentication records or an integrated vault rather than embedding them in scripts. Avoid hard-coded credentials in automation that calls the API (CWE-798). Rotate them on a schedule and scope each credential to the least access a scan needs.

Role-based access control limits who can view findings, run scans, and change configuration. Assign the narrowest role that fits each job, and separate scan operators from administrators who manage credentials and integrations.

API keys and agent activation keys authenticate programmatic and agent access. Treat both as secrets, keep them out of source code, and rotate them (CWE-798). An activation key registers new agents, so a leaked key can enroll unauthorized hosts. Scope keys and review them when staff change roles.

Tenant configuration governs multi-team use. Use asset groups, tags, and business units to keep teams scoped to their own assets. Review integration connectors, since each one carries finding data outside the platform.

## Where it fits in the program

Qualys supplies detection, prioritization, and compliance checking, and connects detection to patching. It answers what is vulnerable, how risky each finding is under TruRisk, and whether the fix held on rescan. VMDR keeps detect and remediate in one place.

In a mature program, Qualys findings open tickets in ServiceNow Vulnerability Response and feed metrics such as mean time to remediate. The QID-based state tracking is what lets those metrics reflect real closure rather than ticket closure alone.

## Resources

- Qualys VMDR documentation
- Qualys Cloud Platform documentation
- Qualys Cloud Agent documentation
- Qualys Patch Management documentation
- Qualys Policy Compliance documentation
- Qualys Web Application Scanning documentation

## Related pages

- /platforms/README.md
- /SCANNER_PLATFORMS_REFERENCE.md
- /VULNERABILITY_MANAGEMENT_REFERENCE.md
- /platforms/tenable.md
- /platforms/rapid7-insightvm.md
- /platforms/servicenow-vr.md
