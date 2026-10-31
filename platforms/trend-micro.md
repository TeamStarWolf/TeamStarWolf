# Trend Vision One (Trend Micro)

Trend Vision One is Trend Micro's extended detection and response (XDR) platform. It brings together endpoint, server, cloud, network, and email sensors into one data lake and console, and includes the workload and cloud-security capabilities formerly branded Cloud One. The platform spans prevention, detection and response, and cloud security posture across hybrid estates. Capability availability depends on the licence and the entitlements in force.

## What it is and where it fits

Trend Vision One is an XDR platform that collects signals from several security layers and correlates them centrally. It fits across the estate rather than at one layer: workloads and servers, containers, cloud accounts, network traffic, endpoints, and email all feed the same platform. A security operations team uses it to protect workloads, assess cloud posture, and run detection and response across those layers from one console.

The capabilities formerly sold as Cloud One are now part of this platform. What a tenant can use depends on the licence and which capabilities are entitled, so confirm entitlement before relying on a specific function.

## Architecture and how it works

The platform is a cloud console and data lake fed by sensors and connectors across each protected layer. Agents run on endpoints and server workloads and send telemetry to the platform. Cloud connectors read configuration and activity from cloud provider accounts. Network sensors inspect traffic inline or out of band. Email protection inspects message flow. Each source contributes its events to the central data lake.

In the data lake, events from the different layers are correlated so that related activity on an endpoint, a workload, and the network can be seen as one chain. Detection analytics run centrally, and the console presents detections, workbench investigations, and posture findings. Policy and configuration reach the agents and connectors from the console.

## Key capabilities

The platform combines protection and posture across layers:

- Workload Security: host-based protection for servers and cloud workloads, including anti-malware, host intrusion prevention (IPS), and virtual patching that shields a known vulnerability at the network layer before a vendor patch is applied.
- Conformity: cloud security posture management that checks cloud accounts against configuration and compliance rules and reports misconfigurations.
- Container Security: image scanning and admission control that evaluates container images and can block non-compliant deployments.
- Network Security: inline intrusion prevention that inspects and blocks malicious traffic.
- Endpoint and email sensors: endpoint protection and email inspection that feed detections into XDR.
- XDR: cross-layer correlation, detections, and the investigation workbench over the shared data lake.

For vulnerability and exposure work, Workload Security produces host IPS and virtual-patching coverage and events, Conformity produces cloud misconfiguration findings, and Container Security produces image findings and admission decisions. XDR produces the correlated detections and the activity used for investigation.

## Deployment and operations

Deployment is a mix of agents and connectors. Workload and endpoint agents install on hosts through existing software tooling or an image. Cloud connectors are configured against each cloud account to read posture and activity. Network sensors are placed in the traffic path. Container Security integrates with the container build pipeline and the cluster admission controller.

Operations run in the Trend Vision One console: detections and the investigation workbench, workload policy, Conformity findings, and container results. Workload Security policy, including which IPS and virtual-patching rules apply, is managed centrally and assigned to host groups. Posture findings from Conformity are triaged and routed to the owning cloud team.

## Integrations and data flow

The XDR data lake is the center of the platform's data flow, holding correlated events from each layer. The platform exposes APIs and connectors to send detections and events to a SIEM for correlation and retention, and to drive response from a SOAR platform. Posture and vulnerability findings can be exported into a vulnerability management workflow or a ticketing system such as ServiceNow so remediation is tracked.

Cloud connectors pull configuration and activity from cloud provider accounts, and the container integration ties into the build and deployment pipeline. These keep the platform's view of cloud and container risk current and feed the same console used for endpoint and network detection.

## Hardening and secure use

Securing the platform itself starts with console access. Use role-based access control so analysts and administrators hold only the roles their work requires, and avoid broad roles where a scoped one is enough (CWE-862: Missing Authorization). Scope access to the business units or accounts a team owns.

Treat API keys as privileged secrets. The platform and its integrations authenticate with API keys, so issue keys with the least scope needed per integration, rotate them, and store them in a secret manager rather than embedding them in scripts, images, or pipeline configuration (CWE-798: Use of Hard-coded Credentials). A hardcoded Vision One or workload API key in a container image or repository is a direct exposure.

Review tenant configuration: confirm which cloud connectors and accounts are linked, keep Workload Security policy in enforce mode once validated rather than detect-only, and set container admission control to block rather than warn where policy requires. Enable multi-factor authentication on console accounts and review the audit log, which records configuration changes, role assignments, and policy edits.

## Where it fits in the program

A vulnerability management and security operations team uses Trend Vision One to cover workloads and cloud as well as endpoints. Workload Security virtual patching buys time on a known vulnerability before the patch lands, Conformity and Container Security surface cloud and image exposure, and XDR gives the SOC correlated detection and response across all of these layers. Findings route into the vulnerability management workflow and ServiceNow, so exposure and active threat across the hybrid estate are tracked in one program.

## Resources

- Trend Vision One documentation
- Trend Vision One Endpoint Security and Workload Security documentation
- Trend Vision One Cloud Posture (Conformity) documentation
- Trend Vision One Container Security documentation
- Trend Vision One API reference

## Related pages

- /platforms/README.md
- /SCANNER_PLATFORMS_REFERENCE.md
- /VULNERABILITY_MANAGEMENT_REFERENCE.md
- /INCIDENT_RESPONSE_REFERENCE.md
- /platforms/crowdstrike-falcon.md
- /platforms/wiz.md
