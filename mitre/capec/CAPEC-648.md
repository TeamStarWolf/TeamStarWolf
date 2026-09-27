# CAPEC-648 — Collect Data from Screen Capture

<a id="capec-648"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium

An adversary gathers sensitive information by exploiting the system's screen capture functionality. Through screenshots, the adversary aims to see what happens on the screen over the course of an operation. The adversary can leverage information gathered in order to carry out further attacks.

## Mapped ATT&CK techniques (2)

- [T1113](/mitre/techniques/T1113.md)
- `T1513`

## Related CWE (1)

[CWE-267](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must have obtained logical access to the system by some means (e.g., via obtained credentials or planting malware on the system).::

**Skills required:** ::SKILL:Once the adversary has logical access (which can potentially require high knowledge and skill level), the adversary needs only to leverage the

**Mitigations:** ::Identify potentially malicious software that may have functionality to acquire screen captures, and audit and/or block it by using allowlist tools.::While screen capture is a legitimate and practical function, certain situations and context may req


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
