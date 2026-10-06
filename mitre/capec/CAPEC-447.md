# CAPEC-447: Design Alteration

<a id="capec-447"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Medium  
Status: Stable  

An adversary modifies the design of a technology, product, or component to acheive a negative impact once the system is deployed. In this type of attack, the goal of the adversary is to modify the design of the system, prior to development starting, in such a way that the negative impact can be leveraged when the system is later deployed. Design alteration attacks differ from development alteration attacks in that design alteration attacks take place prior to development and which then may or may not be developed by the adverary. Design alteration attacks include modifying system designs to degrade system performance, cause unexpected states or errors, and general design changes that may lead to additional vulnerabilities. These attacks generally require insider access to modify design documents, but they may also be spoofed via web communications. The product is then developed and delivered to the user where the negative impact can be leveraged at a later time.

## Prerequisites

- Access to system design documentation prior to the development phase. This access is often obtained via insider access or by leveraging another attack pattern to gain permissions that the adversary wouldn't normally have.
- Ability to forge web communications to deliver modified design documentation.

## Consequences

- Authorization / Execute Unauthorized Commands
- Availability / Unreliable Execution
- Integrity / Alter Execution Logic

## Mitigations

- Assess design documentation prior to development to ensure that they function as intended and without any malicious functionality.
- Ensure that design documentation is saved in a secure location and has proper access controls set in place to avoid unnecessary modification.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
