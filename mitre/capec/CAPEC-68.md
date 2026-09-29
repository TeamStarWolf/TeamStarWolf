# CAPEC-68 — Subvert Code-signing Facilities

<a id="capec-68"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** Low  
**Status:** Draft  

Many languages use code signing facilities to vouch for code's identity and to thus tie code to its assigned privileges within an environment. Subverting this mechanism can be instrumental in an attacker escalating privilege. Any means of subverting the way that a virtual machine enforces code signing classifies for this style of attack.

## Mapped ATT&CK techniques (1)

- [T1553.002 — Code Signing](/mitre/techniques/T1553-002.md) — Adversaries may create, acquire, or steal code signing materials to sign their malware or tools.

## Related CWE (3)

- [CWE-325 — Missing Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html) — The product does not implement a required step in a cryptographic algorithm, resulting in weaker encryption than advertised by the algorithm.
- [CWE-328 — Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html) — The product uses an algorithm that produces a digest (output value) that does not meet security expectations for a hash function that allows an adversary to reasonably determine the original input (preimage attack), find another input that can produce the same hash (2nd preimage attack), or find multiple inputs that evaluate to the same hash (birthday attack).
- [CWE-1326 — Missing Immutable Root of Trust in Hardware](https://cwe.mitre.org/data/definitions/1326.html) — A missing immutable root of trust in the hardware results in the ability to bypass secure boot or execute untrusted or adversarial boot code.

## Prerequisites

- A framework-based language that supports code signing (such as, and most commonly, Java or .NET)
- Deployed code that has been signed by its authoring vendor, or a partner.
- The attacker will, for most circumstances, also need to be able to place code in the victim container. This does not necessarily mean that they will have to subvert host-level security, except when explicitly indicated.

## Skills required

- [High] Subverting code signing is not a trivial activity. Most code signing and verification schemes are based on use of cryptography and the attacker needs to have an understanding of these cryptographic operations in good detail. Additionally the attacker also needs to be aware of the way memory is assigned and accessed by the container since, often, the only way to subvert code signing would be to patch the code in memory. Finally, a knowledge of the platform specific mechanisms of signing and verifying code is a must.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- A given code signing scheme may be fallible due to improper use of cryptography. Developers must never roll out their own cryptography, nor should existing primitives be modified or ignored.
- If an attacker cannot attack the scheme directly, they might try to alter the environment that affects the signing and verification processes. A possible mitigation is to avoid reliance on flags or environment variables that are user-controllable.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
