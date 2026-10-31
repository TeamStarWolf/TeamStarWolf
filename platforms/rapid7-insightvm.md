# Rapid7 InsightVM

Rapid7 InsightVM is a vulnerability management product on the Rapid7 Insight platform. It uses the Nexpose scan engine and the Insight Agent to find and track vulnerabilities across hosts and networks. It sits alongside other Insight products, including InsightIDR for detection and response and InsightConnect for automation. Licence tier and module entitlement decide what is in force; this page does not describe any specific organization's deployment.

## What it is and where it fits

InsightVM covers the vulnerability management part of a security program. It identifies vulnerabilities and misconfigurations, scores them by real risk, and tracks remediation to closure. It is built for ongoing management rather than one-off scanning.

The Insight platform is the shared cloud layer. InsightVM lives on it alongside InsightIDR, a SIEM and detection product, and InsightConnect, a SOAR product for automation and orchestration. Shared platform data lets these products reference the same assets.

InsightVM fits alongside ticketing and SIEM systems as the source of vulnerability findings. Those findings flow out to where remediation is assigned and where telemetry is correlated.

## Architecture and how it works

InsightVM combines three parts: scan engines, the Insight Agent, and a console. The console coordinates scans, stores results, and presents dashboards and reports. Scan engines run the detection work against targets.

The Nexpose engine runs the vulnerability checks. Scan engines deploy inside the environment to reach internal networks and can be distributed across sites. Authenticated scans use managed credentials to read deeper host state than unauthenticated scans.

The Insight Agent installs on hosts and collects data locally, then reports to the platform. Agents suit endpoints that move between networks and systems not always reachable for network scanning. They provide continuous data between full scans.

Data from engines and agents normalizes into assets and vulnerability instances on the platform. Each asset carries attributes and tags. The platform tracks the state of each vulnerability over time, which supports live dashboards.

## Key capabilities

Detections produce vulnerability findings against assets. Each finding ties a specific weakness to the host where it was found, with the evidence the check used. Authenticated results add installed-package and patch-level detail.

The Real Risk score ranks vulnerabilities. It combines vulnerability severity with exploit and malware exposure and the age of the vulnerability into a score on a wider scale than base CVSS. Real Risk drives remediation order by reflecting actual exploitability, not severity alone.

Remediation projects group vulnerabilities into tracked work for the teams that own them. A project sets a scope and a goal, then tracks progress as findings close. This turns a finding list into assigned, measurable work.

Live dashboards update as scan and agent data arrives. They show current risk, trends, and remediation progress without waiting for a scheduled report. Query-based cards let teams build views for their own scope.

Finding state tracks across scans. A vulnerability that no longer appears after remediation closes, and one that reappears is flagged. This supports metrics on whether remediation actually held.

## Deployment and operations

A common pattern pairs distributed scan engines for network ranges with the Insight Agent on endpoints and servers. The console and platform coordinate both. Agents reduce reliance on scan windows for roaming systems.

Authenticated scans need managed credentials, which makes credential handling an operational priority. Scan schedules and engine placement balance coverage against load on target networks. Agent configuration controls collection frequency.

Operations teams maintain scan templates, credential sets, asset tags, and remediation projects. Tags drive dynamic asset groups, scan scope, and dashboard queries. Accurate tagging keeps Real Risk prioritization aligned with business context.

## Integrations and data flow

Findings flow to downstream systems. InsightVM integrates with ServiceNow so vulnerabilities open and update records in ServiceNow Vulnerability Response, where work is assigned and tracked. The integration keeps ticket state aligned with finding state.

SIEM integration sends vulnerability and asset data to log analytics platforms, and InsightVM data can feed InsightIDR within the same platform. Detection teams correlate exposure with alerts and telemetry. InsightConnect can automate response steps across these systems.

InsightVM is the source of vulnerability truth, and ServiceNow and the SIEM consume it. Consistent asset identity across the systems keeps the join reliable.

## Hardening and secure use

Scan credentials are a high-value secret. Store them in the platform's credential management or an integrated vault rather than embedding them in scan templates or scripts. Avoid hard-coded credentials in automation that calls the API (CWE-798). Rotate them on a schedule and scope each credential to the least access a scan needs.

Role-based access control limits who can view findings, run scans, and change configuration. Assign the narrowest role that fits each job. Separate scan operators from administrators who manage credentials and integrations.

API keys authenticate programmatic access to the platform. Treat them as secrets, keep them out of source code, and rotate them (CWE-798). Scope keys to specific use and review them when staff change roles. A leaked key with broad scope exposes the account.

Tenant and console configuration govern multi-team use. Use asset groups and tags to scope teams to their own assets. Review integration connectors, since each one carries finding data outside the platform.

## Where it fits in the program

InsightVM supplies the detection and prioritization layer of vulnerability management, with remediation projects and live dashboards built in. It answers what is vulnerable, how risky each finding is under Real Risk, and whether the fix held on rescan. The project model turns findings into assigned work.

In a mature program, InsightVM findings open tickets in ServiceNow Vulnerability Response and feed metrics such as mean time to remediate. Its place on the Insight platform lets vulnerability data connect to detection in InsightIDR and automation in InsightConnect.

## Resources

- Rapid7 InsightVM documentation
- Rapid7 Insight Agent documentation
- Rapid7 Insight platform documentation
- Nexpose documentation

## Related pages

- /platforms/README.md
- /SCANNER_PLATFORMS_REFERENCE.md
- /VULNERABILITY_MANAGEMENT_REFERENCE.md
- /platforms/tenable.md
- /platforms/qualys.md
- /platforms/servicenow-vr.md
