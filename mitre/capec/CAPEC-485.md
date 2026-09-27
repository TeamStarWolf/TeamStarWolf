# CAPEC-485 — Signature Spoofing by Key Recreation

<a id="capec-485"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

An attacker obtains an authoritative or reputable signer's private signature key by exploiting a cryptographic weakness in the signature algorithm or pseudorandom number generation and then uses this key to forge signatures from the original signer to mislead a victim into performing actions that benefit the attacker.

## Mapped ATT&CK techniques (1)

- [T1552.004](/mitre/techniques/T1552-004.md)

## Related CWE (1)

[CWE-330](/CWE_REFERENCE.md)

**Prerequisites:** ::An authoritative signer is using a weak method of random number generation or weak signing software that causes key leakage or permits key inference.::An authoritative signer is using a signature al

**Skills required:** ::SKILL:Cryptanalysis of signature generation algorithm:LEVEL:High::SKILL:Reverse engineering and cryptanalysis of signature generation algorithm impl

**Mitigations:** ::Ensure cryptographic elements have been sufficiently tested for weaknesses.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
