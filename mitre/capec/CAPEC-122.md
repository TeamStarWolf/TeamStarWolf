# CAPEC-122: Privilege Abuse

<a id="capec-122"></a>

Abstraction: Meta  
Typical severity: Medium  
Likelihood: High  
Status: Draft  

An adversary is able to exploit features of the target that should be reserved for privileged users or administrators but are exposed to use by lower or non-privileged accounts. Access to sensitive information and functionality must be controlled to ensure that only authorized users are able to access these resources.

## Mapped ATT&CK techniques (1)

- [T1548: Abuse Elevation Control Mechanism](/mitre/techniques/T1548.md): Adversaries may circumvent mechanisms designed to control privilege elevation to gain higher-level permissions.

## Related CWE (3)

- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html): The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html): The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.
- [CWE-1317: Improper Access Control in Fabric Bridge](https://cwe.mitre.org/data/definitions/1317.html): The product uses a fabric bridge for transactions between two Intellectual Property (IP) blocks, but the bridge does not properly perform the expected privilege, identity, or other access control checks between those IP blocks.

## Prerequisites

- The target must have misconfigured their access control mechanisms such that sensitive information, which should only be accessible to more trusted users, remains accessible to less trusted users.
- The adversary must have access to the target, albeit with an account that is less privileged than would be appropriate for the targeted resources.

## Skills required

- [Low] Adversary can leverage privileged features they already have access to without additional effort or skill. Adversary is only required to have access to an account with improper priveleges.

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Authorization / Execute Unauthorized Commands
- Authorization / Gain Privileges
- Access Control, Authorization / Bypass Protection Mechanism

## Mitigations

- Configure account privileges such privileged/administrator functionality is not exposed to non-privileged/lower accounts.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
