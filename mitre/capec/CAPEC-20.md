# CAPEC-20: Encryption Brute Forcing

<a id="capec-20"></a>

Abstraction: Standard  
Typical severity: Low  
Likelihood: Low  
Status: Draft  

An attacker, armed with the cipher text and the encryption algorithm used, performs an exhaustive (brute force) search on the key space to determine the key that decrypts the cipher text to obtain the plaintext.

## Related CWE (4)

- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html): The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required.
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html): The product uses a broken or risky cryptographic algorithm or protocol.
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html): The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.
- [CWE-1204: Generation of Weak Initialization Vector (IV)](https://cwe.mitre.org/data/definitions/1204.html): The product uses a cryptographic primitive that uses an Initialization Vector (IV), but the product does not generate IVs that are sufficiently unpredictable or unique according to the expected cryptographic requirements for that primitive.

## Prerequisites

- Ciphertext is known.
- Encryption algorithm and key size are known.

## Skills required

- [Low] Brute forcing encryption does not require much skill.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.
- In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

## Related pages

- [CAPEC-97: Cryptanalysis](/mitre/capec/CAPEC-97.md), also related to CWE-327 and CWE-1204
- [CAPEC-112: Brute Force](/mitre/capec/CAPEC-112.md), also related to CWE-326
- [CAPEC-192: Protocol Analysis](/mitre/capec/CAPEC-192.md), also related to CWE-326
- [CAPEC-459: Creating a Rogue Certification Authority Certificate](/mitre/capec/CAPEC-459.md), also related to CWE-327
- [CAPEC-473: Signature Spoof](/mitre/capec/CAPEC-473.md), also related to CWE-327
- [CAPEC-475: Signature Spoofing by Improper Validation](/mitre/capec/CAPEC-475.md), also related to CWE-327
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [The Year 1995 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1995.md)
- [The Year 1998 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1998.md)
- [The Year 1999 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1999.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
