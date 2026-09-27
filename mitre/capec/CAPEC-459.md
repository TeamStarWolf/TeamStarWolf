# CAPEC-459 — Creating a Rogue Certification Authority Certificate

<a id="capec-459"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium

An adversary exploits a weakness resulting from using a hashing algorithm with weak collision resistance to generate certificate signing requests (CSR) that contain collision blocks in their to be signed parts. The adversary submits one CSR to be signed by a trusted certificate authority then uses the signed blob to make a second certificate appear signed by said certificate authority. Due to the

## Related CWE (3)

[CWE-327](/CWE_REFERENCE.md) [CWE-295](/CWE_REFERENCE.md) [CWE-290](/CWE_REFERENCE.md)

**Prerequisites:** ::Certification Authority is using a hash function with insufficient collision resistance to generate the certificate hash to be signed::

**Skills required:** ::SKILL:Understanding of how to force a hash collision in X.509 certificates:LEVEL:High::SKILL:An attacker must be able to craft two X.509 certificate

**Mitigations:** ::Certification Authorities need to stop using deprecated or cryptographically insecure hashing algorithms to hash the certificates that they are about to sign. Instead they should be using stronger hashing functions such as SHA-256 or SHA-512.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
