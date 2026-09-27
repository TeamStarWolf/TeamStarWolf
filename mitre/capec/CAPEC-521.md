# CAPEC-521 — Hardware Design Specifications Are Altered

<a id="capec-521"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An attacker with access to a manufacturer's hardware manufacturing process documentation alters the design specifications, which introduces flaws advantageous to the attacker once the system is deployed.

## Prerequisites

- Advanced knowledge of hardware capabilities of a manufacturer's product.
- Access to the manufacturer's documentation.

## Skills required

- Ability to read, interpret, and subsequently alter manufacturer's documentation to cause errors in design specifications.:LEVEL:High
- Ab

## Mitigations

- Digitize documents and cryptographically sign them to verify authenticity.
- Password protect documents and make them read-only for unauthorized users.
- Avoid emailing important documents and configurations.
- Ensure deleted files are actually delete

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
