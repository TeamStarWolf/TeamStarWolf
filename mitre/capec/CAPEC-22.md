# CAPEC-22: Exploiting Trust in Client

<a id="capec-22"></a>

Abstraction: Meta  
Typical severity: High  
Likelihood: High  
Status: Draft  

An attack of this type exploits vulnerabilities in client/server communication channel authentication and data integrity. It leverages the implicit trust a server places in the client, or more importantly, that which the server believes is the client. An attacker executes this type of attack by communicating directly with the server where the server believes it is communicating only with a valid client. There are numerous variations of this type of attack.

## Related CWE (5)

- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html): This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html): When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html): The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Prerequisites

- Server software must rely on client side formatted and validated values, and not reinforce these checks on the server side.

## Skills required

- [Medium] The attacker must have fairly detailed knowledge of the syntax and semantics of client/server communications protocols and grammars

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality / Read Data

## Mitigations

- Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.
- Design: Do not rely on client validation or encoding for security purposes.
- Design: Utilize digital signatures to increase authentication assurance.
- Design: Utilize two factor authentication to increase authentication assurance.
- Implementation: Perform input validation for all remote content.

## Related pages

- [CAPEC-59: Session Credential Falsification through Prediction](/mitre/capec/CAPEC-59.md), also related to CWE-200, CWE-290 and 1 more
- [CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data](/mitre/capec/CAPEC-57.md), also related to CWE-287 and CWE-693
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](/mitre/capec/CAPEC-60.md), also related to CWE-200 and CWE-290
- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), also related to CWE-287 and CWE-290
- [CAPEC-473: Signature Spoof](/mitre/capec/CAPEC-473.md), also related to CWE-20 and CWE-290
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-20 and CWE-200
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
