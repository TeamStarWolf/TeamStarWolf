# CAPEC-17 — Using Malicious Files

<a id="capec-17"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

An attack of this type exploits a system's configuration that allows an adversary to either directly access an executable file, for example through shell access; or in a possible worst case allows an adversary to upload a file and then execute it. Web servers, ftp servers, and message oriented middleware systems which have many integration points are particularly vulnerable, because both the progr

## Mapped ATT&CK techniques (2)

- [T1574.005](/mitre/techniques/T1574-005.md)
- [T1574.010](/mitre/techniques/T1574-010.md)

## Related CWE (7)

[CWE-732](/CWE_REFERENCE.md) [CWE-285](/CWE_REFERENCE.md) [CWE-272](/CWE_REFERENCE.md) [CWE-59](/CWE_REFERENCE.md) [CWE-282](/CWE_REFERENCE.md) [CWE-270](/CWE_REFERENCE.md) [CWE-693](/CWE_REFERENCE.md)

**Prerequisites:** ::System's configuration must allow an attacker to directly access executable files or upload files to execute. This means that any access control system that is supposed to mediate communications bet

**Skills required:** ::SKILL:To identify and execute against an over-privileged system interface:LEVEL:Low::

**Mitigations:** ::Design: Enforce principle of least privilege::Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.::Imple


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
