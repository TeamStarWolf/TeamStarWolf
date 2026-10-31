# Zafran

Zafran is a threat exposure management platform that prioritizes risk by whether an exposure is actually exploitable and whether existing controls already mitigate it, then drives high-impact mitigations at scale. It sits between vulnerability scanning and remediation: rather than add another queue of findings, it reduces the queue to what is reachable and not already covered, and it recommends mitigations that use controls the organization already owns. It is described at a product level as generally available in 2026; licence tier and connected integrations decide what is in force.

## What it is and where it fits

A scanner tells you what is vulnerable. Zafran tries to answer the next two questions: can this be reached and exploited in this environment, and is a control already in the path that reduces the risk. By joining scanner findings with the configuration of the security controls around an asset, it separates the exposures that matter from the much larger set that do not, and it points at the fastest mitigation. This is the mitigation-versus-remediation model: a preventive control enabled now while the patch is pending, often in a plane other than the one the vulnerability lives in. See [CTEM Reference](/CTEM_REFERENCE.md) and [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md).

## Architecture and how it works

Zafran is delivered as a hosted service that connects to the existing stack through APIs rather than a new agent. It ingests findings and asset context from vulnerability scanners, endpoint and cloud security, and network and web controls, and it reads the configuration of those controls. It then models exploitability and control coverage for each exposure, and it expresses the remaining risk as a measurable exposure over time. The result is a set of mitigation recommendations, each tied to a specific control product and a mitigation type.

A recurring concept in the platform is upstream mitigation: applying a change at a control that sits in front of many affected assets, so one action reduces exposure across the set rather than one host at a time. This is the compensating-control idea at scale, and it is why the platform ranks mitigations by how much exposure each one removes.

## Key capabilities

- Exploitability-aware prioritization that narrows findings to what is reachable in the environment.
- Control-efficacy analysis that checks whether an existing control already mitigates an exposure before any new work is assigned.
- Mitigation recommendations, each with a title, a recommendation, a mitigation type, a named control product, and the count of assets and vulnerabilities it affects.
- Exposure expressed as a quantity, including exposure measured in days, so mitigations can be ranked by risk removed.
- A query language (ZQL) for filtering exposures and mitigations.
- Mitigation lifecycle tracking, with states such as new, pending approval, rejected, in progress, and completed, and links to an external ticket.

## Deployment and operations

Deployment is connecting the platform to the data sources and controls through API credentials; there is no endpoint agent to roll out. Operations center on reviewing the ranked mitigations, approving and assigning them, and recording the outcome. Because the platform reads control configuration, keeping its connectors current with the live stack is the main upkeep.

## Integrations and data flow

Zafran integrates with the surrounding stack, and its Cortex XSOAR content pack is a clear example of the data flow. The XSOAR integration connects to the Zafran API with a server URL and an API key, and it provides commands to export recommended mitigations (with an optional ZQL filter) and to push mitigation status back to Zafran, carrying a state and optional external ticket identifier and URL. That pattern, pull the prioritized mitigations into the workflow engine and write the result back, is how the platform fits a security-operations pipeline alongside [Cortex XSOAR](/platforms/cortex-xsoar.md), ticketing, and a SIEM.

## Hardening and secure use

The connector credentials are the sensitive element: the API key and the credentials for every data source it reads. Store them in the platform's or the orchestrator's secret store rather than hardcoding them (CWE-798), scope each connected account to read-only where the workflow allows, and apply role-based access and least privilege in the console (CWE-862). Because the platform reads the configuration of other security controls, treat its access to those systems as privileged and audit it.

## Where it fits in the program

Zafran is a process-plane control: it changes which exposures the program works on and how fast, by ranking them on exploitability and existing coverage rather than CVSS alone. In a vulnerability management program it reduces the remediation backlog to the exposures that are both reachable and uncovered, and it surfaces the compensating control that closes the window now. It complements the authoritative scanners in [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md) rather than replacing them.

## Resources

- The Zafran product documentation.
- The Cortex XSOAR content pack and integration documentation for Zafran, which document the commands, the ZQL filter, and the mitigation fields.

## Related pages

- [Security platforms](/platforms/README.md)
- [CTEM Reference](/CTEM_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md)
- [Tenable](/platforms/tenable.md), [Wiz](/platforms/wiz.md), [Cortex XSOAR](/platforms/cortex-xsoar.md)
