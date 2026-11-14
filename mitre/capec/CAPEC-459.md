# CAPEC-459: Creating a Rogue Certification Authority Certificate

<a id="capec-459"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: Medium  
Status: Draft  

An adversary exploits a weakness resulting from using a hashing algorithm with weak collision resistance to generate certificate signing requests (CSR) that contain collision blocks in their "to be signed" parts. The adversary submits one CSR to be signed by a trusted certificate authority then uses the signed blob to make a second certificate appear signed by said certificate authority. Due to the hash collision, both certificates, though different, hash to the same value and so the signed blob works just as well in the second certificate. The net effect is that the adversary's second X.509 certificate, which the Certification Authority has never seen, is now signed and validated by that Certification Authority.

## Related CWE (3)

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html): The product uses a broken or risky cryptographic algorithm or protocol.
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html): The product does not validate, or incorrectly validates, a certificate.
- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html): This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.

## Prerequisites

- Certification Authority is using a hash function with insufficient collision resistance to generate the certificate hash to be signed

## Skills required

- [High] Understanding of how to force a hash collision in X.509 certificates
- [High] An attacker must be able to craft two X.509 certificates that produce the same hash value
- [Medium] Knowledge needed to set up a certification authority

## Consequences

- Access Control, Authentication / Gain Privileges

## Mitigations

- Certification Authorities need to stop using deprecated or cryptographically insecure hashing algorithms to hash the certificates that they are about to sign. Instead they should be using stronger hashing functions such as SHA-256 or SHA-512.

## Related pages

- [CAPEC-475: Signature Spoofing by Improper Validation](/mitre/capec/CAPEC-475.md), also related to CWE-295 and CWE-327
- [CAPEC-473: Signature Spoof](/mitre/capec/CAPEC-473.md), also related to CWE-290 and CWE-327
- [CAPEC-20: Encryption Brute Forcing](/mitre/capec/CAPEC-20.md), also related to CWE-327
- [CAPEC-97: Cryptanalysis](/mitre/capec/CAPEC-97.md), also related to CWE-327
- [CAPEC-608: Cryptanalysis of Cellular Encryption](/mitre/capec/CAPEC-608.md), also related to CWE-327
- [CAPEC-614: Rooting SIM Cards](/mitre/capec/CAPEC-614.md), also related to CWE-327
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The eMudhra Certificate Authority Key Compromise: A 2026 Case Study](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md)
- [The Year 2008 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2008.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
