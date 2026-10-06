# CAPEC-517: Documentation Alteration to Circumvent Dial-down

<a id="capec-517"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Draft  

An attacker with access to a manufacturer's documentation, which include descriptions of advanced technology and/or specific components' criticality, alters the documents to circumvent dial-down functionality requirements. This alteration would change the interpretation of implementation and manufacturing techniques, allowing for advanced technologies to remain in place even though these technologies might be restricted to certain customers, such as nations on the terrorist watch list, giving the attacker on the receiving end of a shipped product access to an advanced technology that might otherwise be restricted.

## Prerequisites

- Advanced knowledge of internal software and hardware components within manufacturer's development environment.
- Access to the manufacturer's documentation.

## Skills required

- [High] Ability to read, interpret, and subsequently alter manufacturer's documentation to prevent dial-down capabilities.
- [High] Ability to stealthly gain access via remote compromise or physical access to the manufacturer's documentation.

## Mitigations

- Digitize documents and cryptographically sign them to verify authenticity.
- Password protect documents and make them read-only for unauthorized users.
- Avoid emailing important documents and configurations.
- Ensure deleted files are actually deleted.
- Maintain backups of the document for recovery and verification.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
