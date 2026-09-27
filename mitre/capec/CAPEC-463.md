# CAPEC-463 — Padding Oracle Crypto Attack

<a id="capec-463"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Status:** Draft  

An adversary is able to efficiently decrypt data without knowing the decryption key if a target system leaks data on whether or not a padding error happened while decrypting the ciphertext. A target system that leaks this type of information becomes the padding oracle and an adversary is able to make use of that oracle to efficiently decrypt data without knowing the decryption key by issuing on average 128*b calls to the padding oracle (where b is the number of bytes in the ciphertext block). In addition to performing decryption, an adversary is also able to produce valid ciphertexts (i.e., perform encryption) by using the padding oracle, all without knowing the encryption key.

## Related CWE (6)

- [CWE-209 — Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) — The product generates an error message that includes sensitive information about its environment, users, or associated data.
- [CWE-514 — Covert Channel](https://cwe.mitre.org/data/definitions/514.html) — A covert channel is a path that can be used to transfer information in a way not intended by the system's designers.
- [CWE-649 — Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking](https://cwe.mitre.org/data/definitions/649.html) — The product uses obfuscation or encryption of inputs that should not be mutable by an external actor, but the product does not use integrity checks to detect if those inputs have been modified.
- [CWE-347 — Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html) — The product does not verify, or incorrectly verifies, the cryptographic signature for data.
- [CWE-354 — Improper Validation of Integrity Check Value](https://cwe.mitre.org/data/definitions/354.html) — The product does not validate or incorrectly validates the integrity check values or checksums of a message.
- [CWE-696 — Incorrect Behavior Order](https://cwe.mitre.org/data/definitions/696.html) — The product performs multiple related behaviors, but the behaviors are performed in the wrong order in ways that may produce resultant weaknesses.

## Prerequisites

- The decryption routine does not properly authenticate the message / does not verify its integrity prior to performing the decryption operation
- The target system leaks data (in some way) on whether a padding error has occurred when attempting to decrypt the ciphertext.
- The padding oracle remains available for enough time / for as many requests as needed for the adversary to decrypt the ciphertext.

## Mitigations

- Design: Use a message authentication code (MAC) or another mechanism to perform verification of message authenticity / integrity prior to decryption
- Implementation: Do not leak information back to the user as to any cryptography (e.g., padding) encountered during decryption.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
