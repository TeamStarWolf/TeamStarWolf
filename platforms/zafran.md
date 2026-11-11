# Zafran

Zafran is a threat exposure management platform that prioritizes risk by whether an exposure is actually exploitable and whether existing controls already mitigate it, then drives high-impact mitigations at scale. It sits between vulnerability scanning and remediation: rather than add another queue of findings, it reduces the queue to what is reachable and not already covered, and it recommends mitigations that use controls the organization already owns. It is described at a product level as generally available in 2026; licence tier and connected integrations decide what is in force.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability management leads and analysts who run, tune or assess Zafran

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,128 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Zafran for vulnerability and exposure management, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[CTEM Reference](/CTEM_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md), [Tenable](/platforms/tenable.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

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

## Adversary perspective

Because Zafran connects to and reads the configuration of many other security controls and holds a ranked map of what is exploitable, adversaries treat it as both a reconnaissance prize and a place to steer mitigation away. The steps to lock the deployment down are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Stealing connector credentials (ATT&CK T1078, Valid Accounts): the platform holds an API key and read credentials for every data source and control it connects to, so a stolen key reaches that whole set ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)).
- Reading the exposure model: the ranked list of what is reachable and uncovered is a precise map of where to attack and which controls are absent, which is direct reconnaissance.
- Suppressing or rejecting mitigations (ATT&CK T1685, Disable or Modify Tools): console access lets an attacker reject or stall mitigations so a real exposure stays open while the queue still looks managed.
- Trusting the model too far: an attacker who knows a control is credited as mitigating an exposure can target the gap the model assumes is closed.

### Residual risk and own exposure

Zafran reasons from the findings and control configuration it is given, so it inherits the blind spots of its sources and can misjudge coverage when a control is misconfigured in a way its connector does not see. Its read access across the control stack is privileged, so the connectors belong in the patch and monitoring scope like any other software.

### Why it matters

A tester targets the connector credentials and the exposure model rather than the assets the model ranks. A defender monitors connector use, mitigation rejections, and changes to control-efficacy assumptions as signals in their own right. See [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) for keeping the control itself in scope and [the red team reference](/RED_TEAM_REFERENCE.md) for the credential and evasion techniques.

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
