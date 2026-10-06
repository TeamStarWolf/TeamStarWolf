# CAPEC-473: Signature Spoof

<a id="capec-473"></a>

Abstraction: Standard  
Status: Draft  

An attacker generates a message or datablock that causes the recipient to believe that the message or datablock was generated and cryptographically signed by an authoritative or reputable source, misleading a victim or victim operating system into performing malicious actions.

## Mapped ATT&CK techniques (2)

- [T1036.001: Invalid Code Signature](/mitre/techniques/T1036-001.md): Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool.
- [T1553.002: Code Signing](/mitre/techniques/T1553-002.md): Adversaries may create, acquire, or steal code signing materials to sign their malware or tools.

## Related CWE (3)

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html): The product uses a broken or risky cryptographic algorithm or protocol.
- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html): This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.

## Prerequisites

- The victim or victim system is dependent upon a cryptographic signature-based verification system for validation of one or more security events or actions.
- The validation can be bypassed via an attacker-provided signature that makes it appear that the legitimate authoritative or reputable source provided the signature.

## Skills required

- [High] Technical understanding of how signature verification algorithms work with data and applications

## Consequences

- Access Control, Authentication / Gain Privileges

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
