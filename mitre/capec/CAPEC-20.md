# CAPEC-20 — Encryption Brute Forcing

<a id="capec-20"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Likelihood:** Low  
**Status:** Draft  

An attacker, armed with the cipher text and the encryption algorithm used, performs an exhaustive (brute force) search on the key space to determine the key that decrypts the cipher text to obtain the plaintext.

## Related CWE (4)

- [CWE-326 — Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-327 — Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [CWE-1204 — Generation of Weak Initialization Vector (IV)](https://cwe.mitre.org/data/definitions/1204.html)

## Prerequisites

- Ciphertext is known.
- Encryption algorithm and key size are known.

## Skills required

- Brute forcing encryption does not require much skill.:LEVEL:Low

## Mitigations

- Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.
- In theory a brute force attack performing an exhaustive key space search will always s

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
