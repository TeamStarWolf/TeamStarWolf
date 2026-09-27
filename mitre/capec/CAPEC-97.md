# CAPEC-97 — Cryptanalysis

<a id="capec-97"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** Low  
**Status:** Draft  

Cryptanalysis is a process of finding weaknesses in cryptographic algorithms and using these weaknesses to decipher the ciphertext without knowing the secret key (instance deduction). Sometimes the weakness is not in the cryptographic algorithm itself, but rather in how it is applied that makes cryptanalysis successful. An attacker may have other goals as well, such as: Total Break (finding the se

## Related CWE (5)

- [CWE-327 — Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-1204 — Generation of Weak Initialization Vector (IV)](https://cwe.mitre.org/data/definitions/1204.html)
- [CWE-1240 — Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)
- [CWE-1241 — Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)
- [CWE-1279 — Cryptographic Operations are run Before Supporting Units are Ready](https://cwe.mitre.org/data/definitions/1279.html)

## Prerequisites

- The target software utilizes some sort of cryptographic algorithm.
- An underlying weaknesses exists either in the cryptographic algorithm used or in the way that it was applied to a particular chunk

## Skills required

- Cryptanalysis generally requires a very significant level of understanding of mathematics and computation.:LEVEL:High

## Mitigations

- Use proven cryptographic algorithms with recommended key sizes.
- Ensure that the algorithms are used properly. That means: 1. Not rolling out your own crypto; Use proven algorithms and implementations. 2. Choosing initialization vectors with suffic

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
