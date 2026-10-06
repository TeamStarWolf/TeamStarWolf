# CAPEC-444: Development Alteration

<a id="capec-444"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Medium  
Status: Stable  

An adversary modifies a technology, product, or component during its development to acheive a negative impact once the system is deployed. The goal of the adversary is to modify the system in such a way that the negative impact can be leveraged when the system is later deployed. Development alteration attacks may include attacks that insert malicious logic into the system's software, modify or replace hardware components, and other attacks which negatively impact the system during development. These attacks generally require insider access to modify source code or to tamper with hardware components. The product is then delivered to the user where the negative impact can be leveraged at a later time.

## Prerequisites

- Access to the system during the development phase to alter and/or modify software and hardware components. This access is often obtained via insider access or by leveraging another attack pattern to gain permissions that the adversary wouldn't normally have.

## Consequences

- Authorization / Execute Unauthorized Commands
- Availability / Unreliable Execution
- Integrity / Alter Execution Logic

## Mitigations

- Assess software and software components during development and prior to deployment to ensure that they function as intended and without any malicious functionality.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
