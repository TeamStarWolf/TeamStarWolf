# CAPEC-620 — Drop Encryption Level

<a id="capec-620"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Status:** Draft  

An attacker forces the encryption level to be lowered, thus enabling a successful attack against the encrypted data.

## Mapped ATT&CK techniques (1)

- [T1600 — Weaken Encryption](/mitre/techniques/T1600.md) — Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications.

## Related CWE (1)

- [CWE-757 — Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html) — A protocol or its implementation supports interaction between multiple actors and allows those actors to negotiate which algorithm should be used as a protection mechanism such as encryption or authentication, but it…

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
