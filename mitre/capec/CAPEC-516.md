# CAPEC-516 — Hardware Component Substitution During Baselining

<a id="capec-516"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary with access to system components during allocated baseline development can substitute a maliciously altered hardware component for a baseline component during the product development and research phases. This can lead to adjustments and calibrations being made in the product so that when the final product, now containing the modified component, is deployed it will not perform as designed and be advantageous to the adversary.

## Mapped ATT&CK techniques (1)

- [T1195.003 — Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md) — Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- The adversary will need either physical access or be able to supply malicious hardware components to the product development facility.

## Skills required

- [Medium] Intelligence data on victim's purchasing habits.
- [High] Resources to maliciously construct/alter hardware components used for testing by the supplier.
- [High] Resources to physically infiltrate supplier.

## Mitigations

- Hardware attacks are often difficult to detect, as inserted components can be difficult to identify or remain dormant for an extended period of time.
- Acquire hardware and hardware components from trusted vendors. Additionally, determine where vendors purchase components or if any components are created/acquired via subcontractors to determine where supply chain risks may exist.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
