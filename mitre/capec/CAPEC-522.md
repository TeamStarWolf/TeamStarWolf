# CAPEC-522 — Malicious Hardware Component Replacement

<a id="capec-522"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary replaces legitimate hardware in the system with faulty counterfeit or tampered hardware in the supply chain distribution channel, with purpose of causing malicious disruption or allowing for additional compromise when the system is deployed.

## Mapped ATT&CK techniques (1)

- [T1195.003 — Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md)

## Prerequisites

- Physical access to the system after it has left the manufacturer but before it is deployed at the victim location.

## Skills required

- Advanced knowledge of the design of the system.:LEVEL:High
- Hardware creation and manufacture of replacement components.:LEVEL:High

## Mitigations

- Ensure that all contractors and sub-suppliers use trusted means of shipping (e.g., bonded/cleared/vetted and insured couriers) to ensure that components, once purchased, are not subject to compromise during their delivery.
- Prevent or detect tamper

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
