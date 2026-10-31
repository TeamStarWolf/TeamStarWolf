# Microsoft Defender for Endpoint

Microsoft Defender for Endpoint is Microsoft's endpoint detection and response platform. It combines prevention, EDR, and Defender Vulnerability Management on devices running Windows, macOS, Linux, and mobile operating systems. It is a component of the Defender XDR suite and is managed from the Microsoft Defender portal. Feature availability depends on the licence plan and the Vulnerability Management entitlement in force.

## What it is and where it fits

Defender for Endpoint protects and monitors endpoints and produces both detections and vulnerability findings. It fits at the device layer and ties into the wider Microsoft security and management stack. The platform uses the endpoint protection built into modern Windows alongside a cloud service that stores telemetry and runs analytics.

The product is part of Defender XDR, so its endpoint signals combine with identity, email, and cloud signals in one portal. What a tenant can use depends on the licence plan; the vulnerability-management features in particular depend on the Defender Vulnerability Management entitlement, either bundled or as an add-on.

## Architecture and how it works

On Windows, the sensor is built into the operating system; onboarding activates it rather than installing a separate agent. On macOS, Linux, and mobile platforms, a Microsoft Defender agent is installed. The sensor collects process, file, network, and registry events and sends them to the Defender cloud service in the organization's tenant.

Analytics, detection, and storage run in the cloud. The portal presents detections, device inventory, vulnerability findings, and the exposure score. Automated investigation and remediation runs in the cloud and can act on devices to contain or remediate without an analyst driving each step. Policy and configuration reach devices through the management channel (Intune, Group Policy, or Configuration Manager), while the sensor itself talks to the Defender service.

## Key capabilities

The platform covers prevention, detection, response, and exposure on the endpoint:

- Attack surface reduction rules: configurable rules that block common attack techniques, such as script and macro abuse.
- Next-generation protection: the antivirus and behavioral prevention engine.
- Endpoint detection and response (EDR): continuous recording and detections mapped to attacker techniques, with investigation timelines.
- Automated investigation and remediation: automated triage and cleanup of alerts, with configurable automation levels.
- Defender Vulnerability Management: device inventory of installed software, security recommendations, and vulnerability findings drawn from the sensor. It also reports misconfigurations and surfaces an exposure score for the device estate.

For vulnerability management, the product produces security recommendations, per-device vulnerability findings (software and known weaknesses), and the exposure score that summarizes device risk. For detection and response, it produces alerts, incidents, and the device timeline.

## Deployment and operations

Onboarding is done through Intune, Group Policy, Configuration Manager, or onboarding scripts, depending on how the estate is managed. For Windows, onboarding activates the built-in sensor; for other platforms, it installs the Defender agent. Devices appear in the portal inventory once onboarded and reporting.

Operations run in the Microsoft Defender portal: incidents and alerts, device inventory, vulnerability findings, and automation settings. Device groups organize the estate and scope both policy and analyst access. Remediation of vulnerability findings is often handed to Intune as a remediation task, so patching and configuration changes are tracked through the management tool.

## Integrations and data flow

As part of Defender XDR, endpoint signals correlate with identity, email, and cloud signals in the same portal. Microsoft Sentinel is the native SIEM target; the Defender connector streams alerts and raw events into Sentinel for correlation and retention. The platform also exposes APIs for alerts, vulnerability data, and device actions.

Vulnerability findings and security recommendations flow into Intune for remediation, and can be exported by API into a vulnerability management workflow or a ticketing system such as ServiceNow. Alerts and incidents can be forwarded to non-Microsoft SIEM and SOAR products through the API and the streaming connector.

## Hardening and secure use

Securing the platform itself starts with access control. Use role-based access control and device groups so analysts see and act only on the devices in their scope; avoid assigning broad built-in roles when a scoped role will do (CWE-862: Missing Authorization). Scope device groups deliberately so that response actions cannot reach out-of-scope hosts.

Enable tamper protection so that Defender settings, including real-time protection and the sensor, cannot be disabled locally by malware or an attacker with local rights. Keep attack surface reduction rules in enforce mode once validated rather than audit-only.

Treat API access as a privileged integration. Register applications with the least API permission needed, prefer certificate credentials over shared secrets, rotate credentials, and store them in a secret store rather than in code or configuration (CWE-798: Use of Hard-coded Credentials). Review the portal audit log, which records configuration changes, role assignments, and response actions, and require multi-factor authentication on accounts that reach the portal.

## Where it fits in the program

A vulnerability management and security operations team uses Defender for Endpoint as both a detection sensor and a vulnerability source on managed devices. Defender Vulnerability Management supplies agent-based findings and an exposure score that complement network scanners, and hands remediation to Intune. The SOC works incidents in the Defender portal and correlates endpoint signals with the rest of Defender XDR and Microsoft Sentinel, keeping exposure and active threat in one view.

## Resources

- Microsoft Defender for Endpoint documentation
- Microsoft Defender Vulnerability Management documentation
- Microsoft Defender XDR documentation
- Microsoft Defender for Endpoint APIs reference

## Related pages

- /platforms/README.md
- /SCANNER_PLATFORMS_REFERENCE.md
- /VULNERABILITY_MANAGEMENT_REFERENCE.md
- /INCIDENT_RESPONSE_REFERENCE.md
- /platforms/crowdstrike-falcon.md
- /platforms/entra-id.md
