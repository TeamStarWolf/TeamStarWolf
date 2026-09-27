# CAPEC-475 — Signature Spoofing by Improper Validation

<a id="capec-475"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary exploits a cryptographic weakness in the signature verification algorithm implementation to generate a valid signature without knowing the key.

## Related CWE (3)

- [CWE-347 — Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [CWE-327 — Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-295 — Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

## Prerequisites

- Recipient is using a weak cryptographic signature verification algorithm or a weak implementation of a cryptographic signature verification algorithm, or the configuration of the recipient's applica

## Skills required

- Cryptanalysis of signature verification algorithm:LEVEL:High
- Reverse engineering and cryptanalysis of signature verification algorithm

## Mitigations

- Use programs and products that contain cryptographic elements that have been thoroughly tested for flaws in the signature verification routines.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
