# CAPEC-477 — Signature Spoofing by Mixing Signed and Unsigned Content

<a id="capec-477"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An attacker exploits the underlying complexity of a data structure that allows for both signed and unsigned content, to cause unsigned data to be processed as though it were signed data.

## Related CWE (3)

- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) — The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.
- [CWE-311 — Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html) — The product does not encrypt sensitive or critical information before storage or transmission.
- [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html) — The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.

## Prerequisites

- Signer and recipient are using complex data storage structures that allow for a mix between signed and unsigned data
- Recipient is using signature verification software that does not maintain separa

## Skills required

- The attacker may need to continuously monitor a stream of signed data, waiting for an exploitable message to appear.:LEVEL:High
- Attacke

## Mitigations

- Ensure the application is fully patched and does not allow the processing of unsigned data as if it is signed data.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
