# CAPEC-520 — Counterfeit Hardware Component Inserted During Product Assembly

<a id="capec-520"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary with either direct access to the product assembly process or to the supply of subcomponents used in the product assembly process introduces counterfeit hardware components into product assembly. The assembly containing the counterfeit components results in a system specifically designed for malicious purposes.

## Mapped ATT&CK techniques (1)

- [T1195.003 — Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md) — Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- The adversary will need either physical access or be able to supply malicious hardware components to the product development facility.

## Skills required

- [High] Resources to maliciously construct components used by the manufacturer.
- [High] Resources to physically infiltrate manufacturer or manufacturer's supplier.

## Mitigations

- Hardware attacks are often difficult to detect, as inserted components can be difficult to identify or remain dormant for an extended period of time.
- Acquire hardware and hardware components from trusted vendors. Additionally, determine where vendors purchase components or if any components are created/acquired via subcontractors to determine where supply chain risks may exist.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
