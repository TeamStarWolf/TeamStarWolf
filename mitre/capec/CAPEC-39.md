# CAPEC-39 — Manipulating Opaque Client-based Data Tokens

<a id="capec-39"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** High

In circumstances where an application holds important data client-side in tokens (cookies, URLs, data files, and so forth) that data can be manipulated. If client or server-side application components reinterpret that data as authentication tokens or data (such as store item pricing or wallet information) then even opaquely manipulating that data may bear fruit for an Attacker. In this pattern an

## Related CWE (9)

[CWE-353](/CWE_REFERENCE.md) [CWE-285](/CWE_REFERENCE.md) [CWE-302](/CWE_REFERENCE.md) [CWE-472](/CWE_REFERENCE.md) [CWE-565](/CWE_REFERENCE.md) [CWE-315](/CWE_REFERENCE.md) [CWE-539](/CWE_REFERENCE.md) [CWE-384](/CWE_REFERENCE.md) [CWE-233](/CWE_REFERENCE.md)

**Prerequisites:** ::An attacker already has some access to the system or can steal the client based data tokens from another user who has access to the system.::For an Attacker to viably execute this attack, some data 

**Skills required:** ::SKILL:If the client site token is obfuscated.:LEVEL:Medium::SKILL:If the client site token is encrypted.:LEVEL:High::

**Mitigations:** ::One solution to this problem is to protect encrypted data with a CRC of some sort. If knowing who last manipulated the data is important, then using a cryptographic message authentication code (or hMAC) is prescribed. However, this guidance is not 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
