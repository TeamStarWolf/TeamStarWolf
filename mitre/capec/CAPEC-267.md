# CAPEC-267 — Leverage Alternate Encoding

<a id="capec-267"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An adversary leverages the possibility to encode potentially harmful input or content used by applications such that the applications are ineffective at validating this encoding standard.

## Mapped ATT&CK techniques (1)

- [T1027 — Obfuscated Files or Information](/mitre/techniques/T1027.md)

## Related CWE (9)

- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html)
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html)
- [CWE-180 — Incorrect Behavior Order: Validate Before Canonicalize](https://cwe.mitre.org/data/definitions/180.html)
- [CWE-181 — Incorrect Behavior Order: Validate Before Filter](https://cwe.mitre.org/data/definitions/181.html)
- [CWE-73 — External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)
- [CWE-692 — Incomplete Denylist to Cross-Site Scripting](https://cwe.mitre.org/data/definitions/692.html)

## Prerequisites

- The application's decoder accepts and interprets encoded characters. Data canonicalization, input filtering and validating is not done properly leaving the door open to harmful characters for the ta

## Skills required

- An adversary can inject different representation of a filtered character in a different encoding.:LEVEL:Low
- An adversary may craft subt

## Mitigations

- Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)
- Assume all input is malicious. Create an all

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
