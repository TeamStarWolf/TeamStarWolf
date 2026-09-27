# CAPEC-39 — Manipulating Opaque Client-based Data Tokens

<a id="capec-39"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** High  
**Status:** Draft  

In circumstances where an application holds important data client-side in tokens (cookies, URLs, data files, and so forth) that data can be manipulated. If client or server-side application components reinterpret that data as authentication tokens or data (such as store item pricing or wallet information) then even opaquely manipulating that data may bear fruit for an Attacker. In this pattern an

## Related CWE (9)

- [CWE-353 — Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-302 — Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)
- [CWE-472 — External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)
- [CWE-565 — Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)
- [CWE-315 — Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)
- [CWE-539 — Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)
- [CWE-384 — Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-233 — Improper Handling of Parameters](https://cwe.mitre.org/data/definitions/233.html)

## Prerequisites

- An attacker already has some access to the system or can steal the client based data tokens from another user who has access to the system.
- For an Attacker to viably execute this attack, some data

## Skills required

- If the client site token is obfuscated.:LEVEL:Medium
- If the client site token is encrypted.:LEVEL:High

## Mitigations

- One solution to this problem is to protect encrypted data with a CRC of some sort. If knowing who last manipulated the data is important, then using a cryptographic message authentication code (or hMAC) is prescribed. However, this guidance is not

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
