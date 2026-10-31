# Orca Security

Orca Security is an agentless cloud-native application protection platform (CNAPP). It reads cloud workloads from the control plane and combines posture, vulnerabilities, misconfigurations, secrets, and identities in one model. The sections below describe the generally available product in 2026. The licence tier a team holds decides which modules are in force.

## What it is and where it fits

Orca Security gives a cloud security team coverage of risk without placing an agent on each workload. It collects data through the cloud provider's APIs and through a technique the vendor calls SideScanning, which reads the storage behind running workloads from outside them.

The platform presents one data model. Posture findings, workload vulnerabilities, misconfigurations, exposed secrets, and identity risks all land in the same place and reference the same assets. That shared model is what lets Orca correlate several weak signals into one prioritized risk.

A team reaches for Orca when it wants broad cloud visibility quickly and prefers to avoid the operational weight of agents. It answers which assets are exposed, which carry vulnerabilities or secrets, and which combinations form an attack path worth fixing first.

## Architecture and how it works

Orca is a vendor-hosted service. A tenant connects each cloud account by granting a scoped role that lets Orca read configuration, metadata, and the storage layer behind workloads. No agent is installed on the workloads themselves.

SideScanning is the core technique. Orca reads the block storage and snapshots that back running instances and containers, then reconstructs their file systems in the platform. From that reconstruction it inventories installed software, finds vulnerabilities, detects secrets, and checks configuration, all without running code inside the workload.

Control-plane data comes from provider APIs. Orca reads account configuration, network exposure, identity and access settings, and resource relationships. This gives the context that turns a raw vulnerability into a ranked risk.

Context-based prioritization is applied across the combined data. Rather than ranking by severity alone, Orca weighs whether a workload is reachable, whether it holds a usable secret, what the identity attached to it can do, and how those factors chain. The result is a short list of risks that matter rather than a flat queue.

## Key capabilities

- Agentless coverage of cloud workloads through SideScanning, with no software to install on the workload.
- Cloud security posture management against policy and compliance frameworks.
- Vulnerability detection on operating systems, packages, and application dependencies found during scanning.
- Secret detection across reconstructed file systems and configuration.
- Misconfiguration and exposure analysis using control-plane context such as network reachability.
- Cloud identity and entitlement analysis that flags excess or risky permissions.
- Attack-path analysis that connects exposure, vulnerability, secret, and identity findings into ranked risks.

## Deployment and operations

Onboarding is connection-based. A team grants Orca a scoped role in each cloud account, confirms that the account appears in the platform, and lets the first scan complete. Because there is no agent, coverage of a newly connected account is reached without touching individual workloads.

Scanning runs on a schedule and on change. New or modified workloads are picked up through the control plane and scanned without manual enrollment. This keeps coverage current as accounts and workloads shift.

Operations focus on triage of the prioritized risk list. A team reviews top risks, confirms ownership, and tracks remediation. Because findings carry context, owners can see why a given risk ranks where it does, which supports faster agreement on what to fix.

Policy and alert routing are configured once and refined over time. Teams enable the frameworks they report against, suppress findings that do not apply with documented reasons, and route alerts to messaging and ticketing so work reaches owners.

## Integrations and data flow

Data flows into Orca from connected cloud accounts through the scoped connector role. The platform reads control-plane configuration and the storage behind workloads, then holds the combined result in its own model.

Outbound, findings integrate with the tools a team already uses. Alerts and tickets route to messaging and work-tracking systems. Risk and vulnerability data can feed a SIEM or data warehouse. An API and automation hooks let findings drive pipelines and workflows.

Because collection is agentless and read-only, the data flow is largely one direction, from the cloud account into Orca and then out to the team's response tooling.

## Hardening and secure use

Grant the connector a scoped read-only role in each cloud account. Orca's model depends on reading configuration and storage, not on changing them, so the connector should not hold write or administrative permissions. A connector with more rights than it needs is a missing-authorization risk (CWE-862) and widens the blast radius if the integration is ever misused.

Use role-based access inside the platform. Separate responders, auditors, and administrators so day-to-day triage does not require tenant-wide control. Review membership regularly and remove access that is no longer needed.

Protect API tokens as sensitive credentials (CWE-798). Keep tokens out of source, images, pipeline files, and shared notes. Store them in a secrets manager, scope them narrowly, rotate them, and revoke any token no longer in use. Hard-coded credentials are a common path to platform compromise.

Review who can change policy, suppress risks, and edit alert routing, since those settings decide what the platform surfaces.

## Where it fits in the program

Orca Security is a strong fit where a team wants fast, broad cloud risk visibility without agent rollout. It feeds the vulnerability management program with workload findings and feeds cloud governance with posture, identity, and exposure findings.

Where a team also runs agent-based runtime tools or another CNAPP such as Wiz or Prisma Cloud, Orca often serves as the agentless breadth layer, with agents reserved for workloads that need live runtime defense. A team should decide which product is the system of record for cloud risk.

## Resources

- Orca Security product documentation
- Orca Security SideScanning technology overview
- Orca Security cloud account onboarding guides
- Orca Security API reference

## Related pages

- /platforms/README.md
- /CLOUD_SECURITY_REFERENCE.md
- /VULNERABILITY_MANAGEMENT_REFERENCE.md
- /platforms/wiz.md
- /platforms/prisma-cloud.md
