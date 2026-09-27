# CAPEC-206 — Signing Malicious Code

<a id="capec-206"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Status:** Draft  

The adversary extracts credentials used for code signing from a production environment and then uses these credentials to sign malicious content with the developer's key. Many developers use signing keys to sign code or hashes of code. When users or applications verify the signatures are accurate they are led to believe that the code came from the owner of the signing key and that the code has not

## Mapped ATT&CK techniques (1)

- [T1553.002 — Code Signing](/mitre/techniques/T1553-002.md)

## Related CWE (1)

- [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)

## Prerequisites

- The targeted developer must use a signing key to sign code bundles. (Note that not doing this is not a defense - it only means that the adversary does not need to steal the signing key before forgin

## Mitigations

- Ensure digital certificates are protected and inaccessible by unauthorized uses.
- If a digital certificate has been compromised it should be revoked and regenerated.
- Even if a piece of software has a valid and trusted digital signature, it should

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
