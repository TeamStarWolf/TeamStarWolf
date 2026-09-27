# CAPEC-76 — Manipulating Web Input to File System Calls

<a id="capec-76"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High

An attacker manipulates inputs to the target software which the target software passes to file system calls in the OS. The goal is to gain access to, and perhaps modify, areas of the file system that the target software did not intend to be accessible.

## Related CWE (11)

[CWE-23](/CWE_REFERENCE.md) [CWE-22](/CWE_REFERENCE.md) [CWE-73](/CWE_REFERENCE.md) [CWE-77](/CWE_REFERENCE.md) [CWE-346](/CWE_REFERENCE.md) [CWE-348](/CWE_REFERENCE.md) [CWE-285](/CWE_REFERENCE.md) [CWE-272](/CWE_REFERENCE.md) [CWE-59](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-15](/CWE_REFERENCE.md)

**Prerequisites:** ::Program must allow for user controlled variables to be applied directly to the filesystem::

**Skills required:** ::SKILL:To identify file system entry point and execute against an over-privileged system interface:LEVEL:Low::

**Mitigations:** ::Design: Enforce principle of least privilege.::Design: Ensure all input is validated, and does not contain file system commands::Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
