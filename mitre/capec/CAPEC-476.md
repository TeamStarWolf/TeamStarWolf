# CAPEC-476 — Signature Spoofing by Misrepresentation

<a id="capec-476"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An attacker exploits a weakness in the parsing or display code of the recipient software to generate a data blob containing a supposedly valid signature, but the signer's identity is falsely represented, which can lead to the attacker manipulating the recipient software or its victim user to perform compromising actions.

## Related CWE (1)

- [CWE-290 — Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html) — This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.

## Prerequisites

- Recipient is using signature verification software that does not clearly indicate potential homographs in the signer identity.Recipient is using signature verification software that contains a parsing vulnerability, or allows control characters in the signer identity field, such that a signature is mistakenly displayed as valid and from a known or authoritative signer.

## Skills required

- [High] Attacker needs to understand the layout and composition of data blobs used by the target application.
- [High] To discover a specific vulnerability, attacker needs to reverse engineer signature parsing, signature verification and signer representation code.
- [High] Attacker may be required to create malformed data blobs and know how to insert them in a location that the recipient will visit.

## Mitigations

- Ensure the application is using parsing and data display techniques that will accurately display control characters, international symbols and markings, and ultimately recognize potential homograph attacks.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
