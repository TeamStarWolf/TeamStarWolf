# SailPoint

SailPoint is an identity security and governance platform. It provisions and removes access, runs access certifications, enforces separation-of-duties policy, and models roles. It is delivered as IdentityIQ for on-premises deployment and as Identity Security Cloud as a service.

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

- `/platforms/README.md`
- `/VULNERABILITY_MANAGEMENT_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/platforms/entra-id.md`
- `/platforms/cyberark.md`
