# CAPEC-519: Documentation Alteration to Cause Errors in System Design

<a id="capec-519"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Draft  

An attacker with access to a manufacturer's documentation containing requirements allocation and software design processes maliciously alters the documentation in order to cause errors in system design. This allows the attacker to take advantage of a weakness in a deployed system of the manufacturer for malicious purposes.

## Prerequisites

- Advanced knowledge of software capabilities of a manufacturer's product.
- Access to the manufacturer's documentation.

## Skills required

- [High] Ability to read, interpret, and subsequently alter manufacturer's documentation to cause errors in system design.
- [High] Ability to stealthly gain access via remote compromise or physical access to the manufacturer's documentation.

## Mitigations

- Digitize documents and cryptographically sign them to verify authenticity.
- Password protect documents and make them read-only for unauthorized users.
- Avoid emailing important documents and configurations.
- Ensure deleted files are actually deleted.
- Maintain multiple instances of the document across different privileged users for recovery and verification.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
