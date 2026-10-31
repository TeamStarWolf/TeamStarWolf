# Wiz

Wiz is an agentless cloud-native application protection platform (CNAPP). It connects to cloud environments through provider APIs and builds a model of resources, configurations, identities, and exposures. Its defining feature is the Security Graph, which relates these elements so that combinations of risk become visible. Licence tier and module entitlement decide which capabilities are in force; this page does not describe any specific organization's deployment.

## What it is and where it fits

Wiz sits in the cloud security part of a program, covering posture, workloads, identities, data, and code. It gives security teams one view of risk across cloud accounts without installing agents on every workload. The scope spans infrastructure, containers, and the pipelines that build them.

A CNAPP combines several cloud security functions that were once separate tools. Wiz brings posture management, workload vulnerability scanning, entitlement analysis, data security, and secrets detection into one platform. The Security Graph is the shared layer that ties them together.

Wiz fits alongside ticketing and SIEM systems. It is the source of cloud risk findings, and those findings flow out to where remediation and correlation happen.

## Architecture and how it works

Wiz connects to cloud providers through their APIs using a connector with a scoped read role. It reads configuration, inventory, identities, and workload metadata. Because collection is API-based, no agent runs on the scanned workloads.

Agentless vulnerability scanning reads workload disk snapshots through the cloud provider rather than running code inside each instance. This finds operating system and package vulnerabilities without an install on the host. It covers running, stopped, and short-lived workloads.

The Security Graph stores resources and the relationships between them. Nodes represent assets, identities, and findings. Edges represent relationships such as network reachability, permission grants, and trust. Queries over the graph find paths and combinations rather than isolated facts.

Wiz Code extends the platform into the development pipeline. An admission controller can evaluate workloads against policy before they are admitted to a cluster. This moves some checks to deploy time rather than after the fact.

## Key capabilities

The Security Graph is the core. It lets analysts see how a low-severity finding on one resource combines with an exposed path and an over-permissioned identity into a real attack path. This is toxic-combination analysis: the risk is in the combination, not any single item.

Cloud security posture management (CSPM) checks cloud configuration against policies and benchmarks. It flags misconfigurations such as public storage, weak logging, or missing encryption. Findings tie back to the specific resource and account.

Cloud infrastructure entitlement management (CIEM) analyzes identities and permissions. It finds over-permissioned roles, unused privileges, and risky access paths. This narrows the blast radius if an identity is compromised.

Agentless vulnerability scanning produces vulnerability findings against workloads, keyed to the affected resource. Data security posture management (DSPM) locates sensitive data and flags where it is exposed. Secrets detection finds exposed keys and tokens in workloads and code.

Findings carry severity and context from the graph. A vulnerability on an internet-facing resource with access to sensitive data ranks above the same vulnerability on an isolated one. The context, not the base severity alone, drives priority.

## Deployment and operations

Deployment starts by connecting cloud accounts through the connector role. Onboarding a new account is an API connection rather than an agent rollout, so coverage can expand quickly. The connector's role scope sets what Wiz can read.

Because scanning is agentless, operations teams do not manage an agent fleet for core coverage. They manage connectors, policies, and the graph queries and rules that define risk. Wiz Code and the admission controller add pipeline and cluster integration points to maintain.

Teams tune policies and risk rules to their environment and review new findings as cloud resources change. Keeping connector roles scoped and current is an ongoing operational task.

## Integrations and data flow

Findings flow to downstream systems. Wiz integrates with ticketing systems so that risks open and update tickets where remediation is assigned and tracked. This routes findings to the owning teams.

SIEM integration sends cloud risk and finding data to log analytics platforms. Detection teams correlate cloud posture with alerts and telemetry. APIs and the graph query interface export data for reporting and custom workflows.

Wiz is the source of cloud risk truth, and ticketing and SIEM systems consume it. Consistent resource identity across the systems keeps the join reliable.

## Hardening and secure use

The connector role is the most sensitive configuration. Scope it to the least privilege the platform needs, which is read access to the resources in scope. An over-broad connector role is excessive authorization that widens exposure if the integration is abused (CWE-862). Review the role grant when cloud environments change.

Role-based access control limits who can view findings and change configuration inside Wiz. Assign the narrowest role that fits each job. Separate users who view findings from administrators who manage connectors and policies.

API tokens authenticate programmatic access. Treat them as secrets, keep them out of source code, and rotate them. Scope tokens to specific use and review them when staff change roles. A leaked token with broad scope exposes the tenant.

Tenant configuration governs multi-team and multi-account use. Scope teams to their own accounts and projects. Review each integration, since every connector and export carries finding data outside the platform.

## Where it fits in the program

Wiz supplies the cloud risk layer of a program. It answers what is misconfigured, what is vulnerable, which identities are over-permissioned, where sensitive data sits, and how these combine into attack paths. The Security Graph is what turns separate findings into prioritized, context-aware risk.

In a mature program, Wiz findings open tickets for the owning cloud teams and feed metrics on cloud risk reduction. The agentless model means coverage tracks the cloud inventory closely, since new accounts connect through APIs rather than agent rollout.

## Resources

- Wiz documentation
- Wiz Security Graph documentation
- Wiz Code documentation

## Related pages

- /platforms/README.md
- /SCANNER_PLATFORMS_REFERENCE.md
- /VULNERABILITY_MANAGEMENT_REFERENCE.md
- /platforms/tenable.md
- /platforms/qualys.md
