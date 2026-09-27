# CAPEC-267 — Leverage Alternate Encoding

<a id="capec-267"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An adversary leverages the possibility to encode potentially harmful input or content used by applications such that the applications are ineffective at validating this encoding standard.

## Mapped ATT&CK techniques (1)

- [T1027](/mitre/techniques/T1027.md)

## Related CWE (9)

[CWE-173](/CWE_REFERENCE.md) [CWE-172](/CWE_REFERENCE.md) [CWE-180](/CWE_REFERENCE.md) [CWE-181](/CWE_REFERENCE.md) [CWE-73](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md) [CWE-692](/CWE_REFERENCE.md)

**Prerequisites:** ::The application's decoder accepts and interprets encoded characters. Data canonicalization, input filtering and validating is not done properly leaving the door open to harmful characters for the ta

**Skills required:** ::SKILL:An adversary can inject different representation of a filtered character in a different encoding.:LEVEL:Low::SKILL:An adversary may craft subt

**Mitigations:** ::Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)::Assume all input is malicious. Create an all


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
