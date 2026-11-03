# Prisma Cloud

Prisma Cloud is the Palo Alto Networks cloud-native application protection platform (CNAPP). It covers posture, workloads, identities, and code across public cloud providers. The sections below describe the generally available product in 2026. The licence tier a team holds decides which modules are in force.

## What it is and where it fits

Prisma Cloud brings several cloud security functions into one product. It performs cloud security posture management (CSPM), cloud workload protection (CWP), cloud infrastructure entitlement management (CIEM), and code security. The aim is coverage from build time through runtime, so findings in source and infrastructure as code can be traced to the running resources they produce.

The platform works across AWS, Azure, Google Cloud, and other providers. It reads configuration, workload, and identity data from each connected account. That data is normalized into a shared model so posture, risk, and entitlement questions can be asked across clouds without per-provider tooling.

A cloud security team uses Prisma Cloud to answer a few recurring questions. Which resources are misconfigured against a policy. Which workloads carry known vulnerabilities. Which identities hold more access than they use. Which risks connect into a single exploitable path.

## Architecture and how it works

Prisma Cloud is delivered as a vendor-hosted service. A tenant connects each cloud account through a connector that grants scoped read access to configuration and metadata. The service ingests that data on a schedule and on change, then evaluates it against policy.

Posture evaluation runs against configuration state pulled from provider APIs. The platform compares resource settings to policy packs and to compliance frameworks, then records each failing resource as a finding with context about the account and region.

Workload protection combines scanning and runtime defense. Images, hosts, functions, and containers can be scanned for vulnerabilities and compliance. A Defender component can run on hosts and clusters to add runtime controls such as process, network, and file activity monitoring.

Code security scans infrastructure as code, container images, and open-source dependencies earlier in the lifecycle. Findings in a template can be linked to the deployed resource, so a team can fix the source rather than only the running instance.

Entitlement analysis reads identity and access configuration across connected accounts. It compares granted permissions to observed use and flags effective permissions that create excess privilege or risky access paths.

## Key capabilities

- Cloud security posture management against policy packs and compliance frameworks, with drift detection on resource configuration.
- Cloud workload protection for hosts, containers, serverless functions, and images, spanning scan-time and runtime.
- Cloud infrastructure entitlement management that measures effective permissions against actual use.
- Code security for infrastructure as code, container images, and software composition, with links from source to deployed resource.
- Vulnerability findings on workloads and images, prioritized with cloud context such as exposure and reachability.
- Attack-path and risk correlation that joins misconfiguration, vulnerability, exposure, and identity into connected findings.
- Compliance reporting mapped to common standards, with evidence drawn from the ingested state.

## Deployment and operations

Onboarding starts by connecting cloud accounts. Each connection uses a scoped role or service principal so the platform can read configuration and metadata without broad write access. Teams typically connect accounts in groups and confirm ingestion before expanding coverage.

Workload runtime defense needs the Defender component deployed to the hosts or clusters that require it. This is often handled through the cluster orchestrator or a host install path, and sized to the workloads in scope.

Policy management is a steady operational task. Teams enable the policy packs that match their standards, suppress findings that do not apply with documented reasons, and route the rest to owners. Alert rules decide which findings notify, which open tickets, and which feed dashboards.

Day-to-day work centers on triage. Findings carry severity, context, and remediation guidance. A team reviews new findings, confirms ownership, and tracks closure. Reporting supports both engineering owners and audit needs.

## Integrations and data flow

Data flows into Prisma Cloud from connected cloud accounts and from scan targets such as registries and code repositories. The platform reads provider configuration APIs, pulls image and dependency data from build and registry systems, and collects runtime telemetry where Defender is deployed.

Outbound, findings reach the tools a team already runs. Alerts and tickets can route to messaging and work-tracking systems. Severity and risk data can feed a SIEM or data lake. The platform exposes an API and supports automation so findings can drive pipelines and workflows.

Code security integrates with source control and CI so scans run during pull requests and builds. That placement lets a team block or warn on risky changes before they reach a cloud account.

## Hardening and secure use

Scope each cloud connector role to the least access it needs. A connector that reads posture and metadata should not hold write or administrative permissions on the account. Over-broad connector roles are a missing-authorization risk (CWE-862), because the integration then carries more authority than its function requires.

Control access inside the platform with role-based access. Give responders, auditors, and administrators distinct roles so routine triage does not require tenant-wide administration. Review role membership on a regular cadence and remove access that is no longer used.

Treat API keys as high-value credentials (CWE-798). Do not embed keys in source, container images, pipeline definitions, or shared configuration. Store them in a secrets manager, scope them to the needed functions, rotate them, and revoke keys that are no longer in use. Hard-coded credentials are a frequent cause of platform-level compromise.

Record who can change policy, suppress findings, and alter alert routing. These controls shape what the platform reports, so changes to them deserve the same review as changes to a firewall rule.

## Where it fits in the program

Prisma Cloud sits at the center of cloud posture and workload coverage for a team that wants one product spanning build to runtime. It feeds the vulnerability management program with workload and image findings, and it feeds cloud governance with posture and entitlement findings.

In a stack that also runs a dedicated CNAPP such as Wiz or Orca Security, a team decides which product is the system of record for cloud risk and uses the others for depth or for comparison. The platform complements endpoint and container-specific tools rather than replacing them.

## Resources

- Prisma Cloud Administrator's Guide
- Prisma Cloud Compute Edition documentation
- Palo Alto Networks Prisma Cloud API reference
- Prisma Cloud onboarding and cloud account connection guides

## Related pages

- [Security platforms](/platforms/README.md)
- [Cloud Security Reference Library](/CLOUD_SECURITY_REFERENCE.md)
- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Palo Alto Networks](/platforms/palo-alto-networks.md)
- [Wiz](/platforms/wiz.md)
- [Orca Security](/platforms/orca-security.md)

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [Prisma Cloud entries](https://teamstarwolf.github.io/intelligence-hub/#/explore?product=prisma-cloud)

<!-- hub-links:end -->
