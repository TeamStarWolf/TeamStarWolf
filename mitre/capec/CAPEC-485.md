# CAPEC-485: Signature Spoofing by Key Recreation

<a id="capec-485"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Draft  

An attacker obtains an authoritative or reputable signer's private signature key by exploiting a cryptographic weakness in the signature algorithm or pseudorandom number generation and then uses this key to forge signatures from the original signer to mislead a victim into performing actions that benefit the attacker.

## Mapped ATT&CK techniques (1)

- [T1552.004: Private Keys](/mitre/techniques/T1552-004.md): Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials.

## Related CWE (1)

- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html): The product uses insufficiently random numbers or values in a security context that depends on unpredictable numbers.

## Prerequisites

- An authoritative signer is using a weak method of random number generation or weak signing software that causes key leakage or permits key inference.
- An authoritative signer is using a signature algorithm with a direct weakness or with poorly chosen parameters that enable the key to be recovered using signatures from that signer.

## Skills required

- [High] Cryptanalysis of signature generation algorithm
- [High] Reverse engineering and cryptanalysis of signature generation algorithm implementation and random number generation
- [High] Ability to create malformed data blobs and know how to present them directly or indirectly to a victim.

## Mitigations

- Ensure cryptographic elements have been sufficiently tested for weaknesses.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
