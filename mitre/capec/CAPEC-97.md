# CAPEC-97: Cryptanalysis

<a id="capec-97"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: Low  
Status: Draft  

Cryptanalysis is a process of finding weaknesses in cryptographic algorithms and using these weaknesses to decipher the ciphertext without knowing the secret key (instance deduction). Sometimes the weakness is not in the cryptographic algorithm itself, but rather in how it is applied that makes cryptanalysis successful. An attacker may have other goals as well, such as: Total Break (finding the secret key), Global Deduction (finding a functionally equivalent algorithm for encryption and decryption that does not require knowledge of the secret key), Information Deduction (gaining some information about plaintexts or ciphertexts that was not previously known) and Distinguishing Algorithm (the attacker has the ability to distinguish the output of the encryption (ciphertext) from a random permutation of bits).

## Related CWE (5)

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html): The product uses a broken or risky cryptographic algorithm or protocol.
- [CWE-1204: Generation of Weak Initialization Vector (IV)](https://cwe.mitre.org/data/definitions/1204.html): The product uses a cryptographic primitive that uses an Initialization Vector (IV), but the product does not generate IVs that are sufficiently unpredictable or unique according to the expected cryptographic requirements for that primitive.
- [CWE-1240: Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html): To fulfill the need for a cryptographic primitive, the product implements a cryptographic algorithm using a non-standard, unproven, or disallowed/non-compliant cryptographic implementation.
- [CWE-1241: Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html): The device uses an algorithm that is predictable and generates a pseudo-random number.
- [CWE-1279: Cryptographic Operations are run Before Supporting Units are Ready](https://cwe.mitre.org/data/definitions/1279.html): Performing cryptographic operations without ensuring that the supporting inputs are ready to supply valid data may compromise the cryptographic result.

## Prerequisites

- The target software utilizes some sort of cryptographic algorithm.
- An underlying weaknesses exists either in the cryptographic algorithm used or in the way that it was applied to a particular chunk of plaintext.
- The encryption algorithm is known to the attacker.
- An attacker has access to the ciphertext.

## Skills required

- [High] Cryptanalysis generally requires a very significant level of understanding of mathematics and computation.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Use proven cryptographic algorithms with recommended key sizes.
- Ensure that the algorithms are used properly. That means: 1. Not rolling out your own crypto; Use proven algorithms and implementations. 2. Choosing initialization vectors with sufficiently random numbers 3. Generating key material using good sources of randomness and avoiding known weak keys 4. Using proven protocols and their implementations. 5. Picking the most appropriate cryptographic algorithm for your usage context and data

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
