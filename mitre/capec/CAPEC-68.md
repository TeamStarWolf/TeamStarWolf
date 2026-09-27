# CAPEC-68 — Subvert Code-signing Facilities

<a id="capec-68"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** Low

Many languages use code signing facilities to vouch for code's identity and to thus tie code to its assigned privileges within an environment. Subverting this mechanism can be instrumental in an attacker escalating privilege. Any means of subverting the way that a virtual machine enforces code signing classifies for this style of attack.

## Mapped ATT&CK techniques (1)

- [T1553.002](/mitre/techniques/T1553-002.md)

## Related CWE (3)

[CWE-325](/CWE_REFERENCE.md) [CWE-328](/CWE_REFERENCE.md) [CWE-1326](/CWE_REFERENCE.md)

**Prerequisites:** ::A framework-based language that supports code signing (such as, and most commonly, Java or .NET)::Deployed code that has been signed by its authoring vendor, or a partner.::The attacker will, for mo

**Skills required:** ::SKILL:Subverting code signing is not a trivial activity. Most code signing and verification schemes are based on use of cryptography and the attacke

**Mitigations:** ::A given code signing scheme may be fallible due to improper use of cryptography. Developers must never roll out their own cryptography, nor should existing primitives be modified or ignored.::If an attacker cannot attack the scheme directly, they m


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
