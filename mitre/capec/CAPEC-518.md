# CAPEC-518 — Documentation Alteration to Produce Under-performing Systems

<a id="capec-518"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An attacker with access to a manufacturer's documentation alters the descriptions of system capabilities with the intent of causing errors in derived system requirements, impacting the overall effectiveness and capability of the system, allowing an attacker to take advantage of the introduced system capability flaw once the system is deployed.

## Prerequisites

- Advanced knowledge of software and hardware capabilities of a manufacturer's product.
- Access to the manufacturer's documentation.

## Skills required

- Ability to read, interpret, and subsequently alter manufacturer's documentation to misrepresent system capabilities.:LEVEL:High
- Ability

## Mitigations

- Digitize documents and cryptographically sign them to verify authenticity.
- Password protect documents and make them read-only for unauthorized users.
- Avoid emailing important documents and configurations.
- Ensure deleted files are actually delete

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
