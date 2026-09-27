# CAPEC-159 — Redirect Access to Libraries

<a id="capec-159"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

An adversary exploits a weakness in the way an application searches for external libraries to manipulate the execution flow to point to an adversary supplied library or code base. This pattern of attack allows the adversary to compromise the application or server via the execution of unauthorized code. An application typically makes calls to functions that are a part of libraries external to the a

## Mapped ATT&CK techniques (1)

- [T1574.008](/mitre/techniques/T1574-008.md)

## Related CWE (1)

[CWE-706](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must utilize external libraries and must fail to verify the integrity of these libraries before using them.::

**Skills required:** ::SKILL:To modify the entries in the configuration file pointing to malicious libraries:LEVEL:Low::SKILL:To force symlink and timing issues for redire

**Mitigations:** ::Implementation: Restrict the permission to modify the entries in the configuration file.::Implementation: Check the integrity of the dynamically linked libraries before use them.::Implementation: Use obfuscation and other techniques to prevent reve


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
