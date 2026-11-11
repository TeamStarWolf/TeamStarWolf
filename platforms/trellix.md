# Trellix

Trellix is an endpoint and extended detection and response vendor formed from the combination of McAfee Enterprise and FireEye. Its product line covers Endpoint Security, Trellix XDR, data protection, and threat intelligence. Management centers on ePolicy Orchestrator, known as ePO, the console that deploys agents, applies policy, and collects events.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Endpoint security engineers and SOC analysts who run, tune or assess Trellix

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,331 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Trellix for endpoint protection, detection and response, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Microsoft Defender for Endpoint](/platforms/microsoft-defender.md), [Trend Vision One (Trend Micro)](/platforms/trend-micro.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Trellix sits in the endpoint protection (EPP), endpoint detection and response (EDR), and extended detection and response (XDR) categories, with added data protection and intelligence capabilities. The McAfee Enterprise heritage brings endpoint protection and the ePO management model. The FireEye heritage brings detection engineering and threat intelligence depth.

For a security operations and vulnerability management program, Trellix provides endpoint prevention and detection, data loss controls, and intelligence to enrich decisions. ePO gives one console for policy, deployment, and reporting across the protected estate. Licence tier and module entitlement decide what is in force, including XDR scope, data protection modules, and intelligence feeds.

## Architecture and how it works

Endpoints run the Trellix agent, historically the McAfee Agent, which communicates with ePO. ePO can run on-premises or in a Trellix-hosted model, and it serves as the policy and reporting hub. The agent enforces policy locally and reports events back to ePO for aggregation.

Trellix Endpoint Security provides the prevention and detection modules on the host. These include threat prevention, firewall, web control, and adaptive detection that scores behavior. Policies are authored in ePO and assigned to systems through the ePO system tree, a hierarchy that groups managed endpoints.

Trellix XDR correlates detections across endpoint and other connected sources, adding investigation and response workflows. It draws on Trellix threat intelligence to add context to detections. Data protection modules add data loss prevention and encryption controls managed through the same console.

ePO is the operational center. It deploys agents, distributes content and policy, and collects events into a database for reporting and query. Content updates, including detection logic, flow through ePO to the agents on a schedule.

## Key capabilities

- Endpoint Security with threat prevention, firewall, web control, and adaptive behavioral detection.
- Trellix XDR for cross-source detection correlation, investigation, and response.
- Data protection modules, including data loss prevention and encryption.
- Threat intelligence that enriches detections with context from the FireEye heritage.
- ePolicy Orchestrator as the deployment, policy, and reporting console.
- Centralized event collection and reporting across the managed estate.
- Flexible deployment of ePO on-premises or in a Trellix-hosted model.

Feature availability follows the licensed module set. A tenant may run endpoint protection with ePO alone or add XDR, data protection, and intelligence.

## Deployment and operations

Agents deploy from ePO, through a deployment package, or through standard software distribution tools. The ePO system tree organizes endpoints into groups that inherit policy, which simplifies assignment at scale. Begin with baseline policies, confirm behavior in the environment, then tighten threat prevention and access protection rules.

Operational work includes maintaining content updates, reviewing events, and tuning exclusions. Scope exclusions narrowly to a path, process, or signer rather than a broad directory, because wide exclusions open blind spots. Keep ePO, its database, and agent content current so detection logic stays effective.

ePO health matters as much as agent health. Monitor repository replication, agent check-in, and content distribution so no part of the estate falls behind. Track coverage so every managed system reports in and runs the intended policy. Where ePO runs on-premises, protect the server and its database as part of operations.

## Integrations and data flow

Trellix exports events from ePO to SIEM platforms for correlation and archival. Connectors and the ePO data model forward endpoint and XDR events into a central store. Verify the supported connector and event format for the entitled tier before relying on it.

SOAR platforms consume Trellix alerts and call platform APIs to drive automated response. The API and ePO interfaces also support custom reporting and bulk management. Treat these interfaces as a control plane because they can change policy and trigger response across many systems.

Trellix intelligence feeds enrich detections, and the platform can ingest external intelligence to inform scoring. Data protection events flow into the same reporting and correlation paths. This shared flow lets endpoint, data, and intelligence signals inform one investigation.

## Adversary perspective

Because Trellix is the prevention and detection control on the host, adversaries treat it as something to blind or disable, and its agent and the ePO console are themselves an attack surface. The steps to lock the platform down are in the "Hardening and secure use" section that follows.

### Evasion and tampering

- Impairing the agent (ATT&CK T1685, Disable or Modify Tools): with local administrator rights an attacker tries to stop or remove the agent, block its check-in to ePO, or disable threat prevention. Access protection rules and self-protection features are the countermeasures.
- Running below or around the agent: bring-your-own-vulnerable-driver (BYOVD) and user-mode unhooking aim to act outside the agent's visibility, and an over-broad exclusion becomes a safe harbor to run from.
- ePO and API abuse: a hijacked ePO session or a stolen service-account credential lets an attacker change policy or deploy a package across the system tree, which turns the management plane into a foothold ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)).

### Residual risk and own exposure

The agent runs with high privilege on every host, and ePO can push software estate-wide, so a flaw in either is high-impact, and endpoint and management agents across the industry have carried privilege-escalation and remote issues. Where ePO runs on-premises, the server and its database are additional targets. The agent, the ePO server, and its integrations belong in the patch and monitoring scope, and no agent catches every technique on its own.

### Why it matters

Treating the endpoint control as infallible is the mistake. A mature program monitors the control's own health, including agent removals, policy changes, and check-in gaps, as a detection signal, and keeps the agent and ePO current. See [the red team reference](/RED_TEAM_REFERENCE.md) for the evasion techniques and [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) for keeping the control itself in scope.

## Hardening and secure use

Apply ePO role-based access so each administrator holds only the permission set their duties require. Separate read-only reporting roles from administrators who can change policy or deploy software. Review permission sets on a schedule and remove access that is no longer needed, because over-broad roles are an authorization weakness (CWE-862, missing authorization).

Protect API credentials and ePO service accounts as secrets. A credential embedded in a script or integration is a credential exposure risk (CWE-798, use of hard-coded credentials). Store credentials in a secrets manager, scope them narrowly, and rotate them on a defined cadence. Revoke credentials and disable accounts that are unused.

Protect agent integrity so an attacker with local privileges cannot disable or tamper with protection. Use access protection rules and the platform's self-protection features to guard agent processes and files. Keep the agent and content current so protection and integrity checks stay effective.

Enforce multi-factor authentication for ePO sign-in and prefer federation through the organization's identity provider. Where ePO runs on-premises, harden the server operating system, restrict network access to the console, and protect the backing database. Keep policy consistent so no group of systems drifts into a weaker posture.

## Where it fits in the program

Trellix is the endpoint prevention and detection layer, with data protection and intelligence alongside. In a vulnerability management program, it provides the execution-level visibility that scanner findings cannot, plus controls over sensitive data movement. A scanner reports exposure; Trellix reports whether a host is acting maliciously or leaking data.

Threat intelligence from Trellix helps rank which exposures matter against active adversary behavior. Feeding ePO and XDR events into the SIEM and SOAR links exposure data to detection and response. Data protection events add a view of where sensitive data sits and moves across the estate.

## Resources

- Trellix ePolicy Orchestrator (ePO) product documentation
- Trellix Endpoint Security product documentation
- Trellix XDR documentation
- Trellix data protection product documentation
- Trellix threat intelligence documentation

## Related pages

- [Platforms index](/platforms/README.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Microsoft Defender](/platforms/microsoft-defender.md)
- [Trend Micro](/platforms/trend-micro.md)
- [Bitdefender GravityZone](/platforms/bitdefender.md)
