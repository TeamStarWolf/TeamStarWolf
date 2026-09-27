# CAPEC-517 — Documentation Alteration to Circumvent Dial-down

<a id="capec-517"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An attacker with access to a manufacturer's documentation, which include descriptions of advanced technology and/or specific components' criticality, alters the documents to circumvent dial-down functionality requirements. This alteration would change the interpretation of implementation and manufacturing techniques, allowing for advanced technologies to remain in place even though these technolog

## Prerequisites

- Advanced knowledge of internal software and hardware components within manufacturer's development environment.
- Access to the manufacturer's documentation.

## Skills required

- Ability to read, interpret, and subsequently alter manufacturer's documentation to prevent dial-down capabilities.:LEVEL:High
- Ability t

## Mitigations

- Digitize documents and cryptographically sign them to verify authenticity.
- Password protect documents and make them read-only for unauthorized users.
- Avoid emailing important documents and configurations.
- Ensure deleted files are actually delete

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
