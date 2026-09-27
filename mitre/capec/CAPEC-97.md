# CAPEC-97 — Cryptanalysis

<a id="capec-97"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** Low

Cryptanalysis is a process of finding weaknesses in cryptographic algorithms and using these weaknesses to decipher the ciphertext without knowing the secret key (instance deduction). Sometimes the weakness is not in the cryptographic algorithm itself, but rather in how it is applied that makes cryptanalysis successful. An attacker may have other goals as well, such as: Total Break (finding the se

## Related CWE (5)

[CWE-327](/CWE_REFERENCE.md) [CWE-1204](/CWE_REFERENCE.md) [CWE-1240](/CWE_REFERENCE.md) [CWE-1241](/CWE_REFERENCE.md) [CWE-1279](/CWE_REFERENCE.md)

**Prerequisites:** ::The target software utilizes some sort of cryptographic algorithm.::An underlying weaknesses exists either in the cryptographic algorithm used or in the way that it was applied to a particular chunk

**Skills required:** ::SKILL:Cryptanalysis generally requires a very significant level of understanding of mathematics and computation.:LEVEL:High::

**Mitigations:** ::Use proven cryptographic algorithms with recommended key sizes.::Ensure that the algorithms are used properly. That means: 1. Not rolling out your own crypto; Use proven algorithms and implementations. 2. Choosing initialization vectors with suffic


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
