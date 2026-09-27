# CAPEC-35 — Leverage Executable Code in Non-Executable Files

<a id="capec-35"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High

An attack of this type exploits a system's trust in configuration and resource files. When the executable loads the resource (such as an image file or configuration file) the attacker has modified the file to either execute malicious code directly or manipulate the target process (e.g. application server) to execute based on the malicious configuration parameters. Since systems are increasingly in

## Mapped ATT&CK techniques (3)

- [T1027.006](/mitre/techniques/T1027-006.md)
- [T1027.009](/mitre/techniques/T1027-009.md)
- [T1564.009](/mitre/techniques/T1564-009.md)

## Related CWE (8)

[CWE-94](/CWE_REFERENCE.md) [CWE-96](/CWE_REFERENCE.md) [CWE-95](/CWE_REFERENCE.md) [CWE-97](/CWE_REFERENCE.md) [CWE-272](/CWE_REFERENCE.md) [CWE-59](/CWE_REFERENCE.md) [CWE-282](/CWE_REFERENCE.md) [CWE-270](/CWE_REFERENCE.md)

**Prerequisites:** ::The attacker must have the ability to modify non-executable files consumed by the target software.::

**Skills required:** ::SKILL:To identify and execute against an over-privileged system interface:LEVEL:Low::

**Mitigations:** ::Design: Enforce principle of least privilege::Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.::Imple


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
