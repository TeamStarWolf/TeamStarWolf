# SailPoint

SailPoint is an identity security and governance platform. It provisions and removes access, runs access certifications, enforces separation-of-duties policy, and models roles. It is delivered as IdentityIQ for on-premises deployment and as Identity Security Cloud as a service.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Identity governance and access engineers who run, tune or assess SailPoint

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (1,022 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running SailPoint for identity governance and administration, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Microsoft Entra ID](/platforms/entra-id.md), [CyberArk](/platforms/cyberark.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Governance answers who has access to what, why they have it, and whether they still should. SailPoint collects entitlements from connected systems, maps them to identities, and applies policy and review to that picture.

For an identity and security team, SailPoint is the authority for access lifecycle and attestation. It links an identity in the HR source to accounts and entitlements across the estate. It drives joiner, mover, and leaver changes and the recurring reviews that frameworks require.

A licence tier and edition decide which capabilities are in force. IdentityIQ and Identity Security Cloud differ in deployment and feature set. Confirm the edition before assuming a given capability.

## Architecture and how it works

SailPoint builds an identity cube for each person. The cube aggregates accounts and entitlements from every connected system and ties them to the authoritative identity. This is the model that policy and review operate on.

Connectors read and write to target systems. Aggregation pulls current entitlements in so the platform knows actual state. Provisioning pushes changes out so requested or lifecycle-driven access is applied at the source.

Policy runs against the model. Separation-of-duties rules flag toxic combinations. Certification campaigns present each reviewer with the access they own so they can approve or revoke. A role model groups entitlements so access can be granted by business role rather than one entitlement at a time.

## Key capabilities

- Provisioning and deprovisioning that create, change, and remove access on connected systems.
- Access certifications that ask reviewers to confirm or revoke access on a schedule.
- Separation-of-duties policy that detects and blocks conflicting entitlement combinations.
- A role model that bundles entitlements into business roles for consistent granting.
- Joiner, mover, and leaver lifecycle automation driven by the authoritative source.
- Entitlement analytics that surface outliers and unused access.

## Deployment and operations

IdentityIQ is installed and run on infrastructure the team operates. Identity Security Cloud is delivered as a service with a lightweight connectivity component for reaching on-premises systems. Both aggregate from and provision to connected targets.

Onboarding is staged by connector. The authoritative source is connected first, then high-value target systems, then the long tail. Each connector is configured for aggregation, for provisioning, or for both.

Operations teams monitor aggregation runs, provisioning failures, and certification progress. They tune role and policy definitions as the estate changes. Connector service accounts are rotated and their activity is reviewed.

## Integrations and data flow

Target systems integrate through connectors for directories, applications, databases, cloud platforms, and privileged access systems. Aggregation reads current state and provisioning writes approved changes.

The HR system acts as the authoritative source for identities. A new hire, a transfer, or a termination there triggers the matching joiner, mover, or leaver action across connected systems.

Governance events, access grants, revocations, certification decisions, flow to monitoring and ticketing platforms. See `/platforms/servicenow-vr.md` for a downstream workflow consumer. CyberArk and similar privileged systems can be targets under governance; see `/platforms/cyberark.md`.

## Adversary perspective

SailPoint is the authority for access lifecycle and holds privileged connector accounts that read and write across the estate, so adversaries treat it as a high-value target and a way to grant themselves access. The steps to lock it down are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Connector service-account theft (ATT&CK T1078, Valid Accounts): the accounts that let SailPoint provision to directories, databases, and cloud platforms are broadly privileged, so stealing one gives write access across many systems at once.
- Provisioning and policy abuse (T1098): an attacker with governance rights can grant entitlements, approve their own request, or weaken a separation-of-duties rule to create standing access that looks legitimate.
- Rubber-stamped certifications ([CWE-862](https://cwe.mitre.org/data/definitions/862.html)): a reviewer who approves every item lets privilege creep and orphaned access persist, so the control records approval without enforcing least privilege.
- Stale and orphaned accounts: access a leaver kept, or an account the authoritative source never drove, is a foothold the governance model is meant to close but often misses.

### Residual risk and own exposure

Governance-platform compromise is high-impact because it can both read the entire entitlement map and write access across connected systems. The connector credentials and the self-run IdentityIQ instance belong in the patch, secret-rotation, and monitoring scope, and governance cannot stop misuse of access it already approved.

### Why it matters

A tester looks for over-privileged connector accounts, bulk approvals, and failed deprovisioning; a defender monitors provisioning events, policy edits, and certification outcomes. See [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) and [the red team reference](/RED_TEAM_REFERENCE.md).

## Hardening and secure use

Apply least privilege to the platform's own administration. Separate the roles that design policy, run campaigns, and operate connectors so no single account holds unchecked governance power.

Handle connector credentials carefully. The service accounts that let SailPoint read and write to target systems are high value. Embedding them in configuration or scripts maps to CWE-798 Use of Hard-coded Credentials. Store them in a secrets manager and rotate them.

Make certifications meaningful rather than rubber-stamped. A reviewer who approves every item without reading it defeats the control. Entitlements accumulate and least privilege erodes, which maps to CWE-862 Missing Authorization. Use targeted campaigns, revoke-on-no-response defaults, and analytics that flag bulk approvals.

Drive deprovisioning from the authoritative source so a leaver's access is removed promptly. Orphaned accounts left after a departure are a recurring finding and an attacker foothold.

## Where it fits in the program

SailPoint is the governance layer that keeps access aligned with need over time. It counters privilege creep, the slow accumulation of entitlements that outlast the reason they were granted.

Its certification records and policy evidence support audit and compliance attestation. Its provisioning and lifecycle data feed identity monitoring, and a failure to deprovision a leaver is an input to incident response.

## Resources

- SailPoint documentation
- SailPoint IdentityIQ documentation
- SailPoint Identity Security Cloud documentation
- SailPoint connectivity documentation

## Related pages

- [Security platforms](/platforms/README.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Incident Response Reference Library](/INCIDENT_RESPONSE_REFERENCE.md)
- [Microsoft Entra ID](/platforms/entra-id.md)
- [CyberArk](/platforms/cyberark.md)
