# CAPEC-517: Documentation Alteration to Circumvent Dial-down

<a id="capec-517"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Draft  
OpenCRE: [CAPEC-517](https://opencre.org/smartlink/standard/CAPEC/517)  

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

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
