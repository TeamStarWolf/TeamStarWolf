# CAPEC-473 — Signature Spoof

<a id="capec-473"></a>

**Abstraction:** Standard  
**Status:** Draft  

An attacker generates a message or datablock that causes the recipient to believe that the message or datablock was generated and cryptographically signed by an authoritative or reputable source, misleading a victim or victim operating system into performing malicious actions.

## Mapped ATT&CK techniques (2)

- [T1036.001 — Invalid Code Signature](/mitre/techniques/T1036-001.md)
- [T1553.002 — Code Signing](/mitre/techniques/T1553-002.md)

## Related CWE (3)

- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-327 — Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-290 — Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

## Prerequisites

- The victim or victim system is dependent upon a cryptographic signature-based verification system for validation of one or more security events or actions.
- The validation can be bypassed via an att

## Skills required

- Technical understanding of how signature verification algorithms work with data and applications:LEVEL:High

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
