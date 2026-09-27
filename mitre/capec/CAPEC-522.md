# CAPEC-522 — Malicious Hardware Component Replacement

<a id="capec-522"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary replaces legitimate hardware in the system with faulty counterfeit or tampered hardware in the supply chain distribution channel, with purpose of causing malicious disruption or allowing for additional compromise when the system is deployed.

## Mapped ATT&CK techniques (1)

- [T1195.003 — Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md) — Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- Physical access to the system after it has left the manufacturer but before it is deployed at the victim location.

## Skills required

- [High] Advanced knowledge of the design of the system.
- [High] Hardware creation and manufacture of replacement components.

## Mitigations

- Ensure that all contractors and sub-suppliers use trusted means of shipping (e.g., bonded/cleared/vetted and insured couriers) to ensure that components, once purchased, are not subject to compromise during their delivery.
- Prevent or detect tampering with critical hardware or firmware components while in transit through use of state-of-the-art anti-tamper devices.
- Use tamper-resistant and tamper-evident packaging when shipping critical components (e.g., plastic coating for circuit boards, tamper tape, paint, sensors, and/or seals for cases and containers) and inspect received system components for evidence of tampering.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
