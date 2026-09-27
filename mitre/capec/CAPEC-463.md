# CAPEC-463 — Padding Oracle Crypto Attack

<a id="capec-463"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** 

An adversary is able to efficiently decrypt data without knowing the decryption key if a target system leaks data on whether or not a padding error happened while decrypting the ciphertext. A target system that leaks this type of information becomes the padding oracle and an adversary is able to make use of that oracle to efficiently decrypt data without knowing the decryption key by issuing on av

## Related CWE (6)

[CWE-209](/CWE_REFERENCE.md) [CWE-514](/CWE_REFERENCE.md) [CWE-649](/CWE_REFERENCE.md) [CWE-347](/CWE_REFERENCE.md) [CWE-354](/CWE_REFERENCE.md) [CWE-696](/CWE_REFERENCE.md)

**Prerequisites:** ::The decryption routine does not properly authenticate the message / does not verify its integrity prior to performing the decryption operation::The target system leaks data (in some way) on whether 

**Mitigations:** ::Design: Use a message authentication code (MAC) or another mechanism to perform verification of message authenticity / integrity prior to decryption::Implementation: Do not leak information back to the user as to any cryptography (e.g., padding) en


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
