# CAPEC-270 — Modification of Registry Run Keys

<a id="capec-270"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium

An adversary adds a new entry to the run keys in the Windows registry so that an application of their choosing is executed when a user logs in. In this way, the adversary can get their executable to operate and run on the target system with the authorized user's level of permissions. This attack is a good way for an adversary to run persistent spyware on a user's machine, such as a keylogger.

## Mapped ATT&CK techniques (2)

- [T1547.001](/mitre/techniques/T1547-001.md)
- [T1547.014](/mitre/techniques/T1547-014.md)

## Related CWE (1)

[CWE-15](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must have gained access to the target system via physical or logical means in order to carry out this attack.::

**Mitigations:** ::Identify programs that may be used to acquire process information and block them by using a software restriction policy or tools that restrict program execution by using a process allowlist.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
