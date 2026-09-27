# CAPEC-40 — Manipulating Writeable Terminal Devices

<a id="capec-40"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

This attack exploits terminal devices that allow themselves to be written to by other users. The attacker sends command strings to the target terminal device hoping that the target user will hit enter and thereby execute the malicious command with their privileges. The attacker can send the results (such as copying /etc/passwd) to a known directory and collect once the attack has succeeded.

## Related CWE (1)

[CWE-77](/CWE_REFERENCE.md)

**Prerequisites:** ::User terminals must have a permissive access control such as world writeable that allows normal users to control data on other user's terminals.::

**Skills required:** ::SKILL:Ability to discover permissions on terminal devices. Of course, brute force can also be used.:LEVEL:Low::

**Mitigations:** ::Design: Ensure that terminals are only writeable by named owner user and/or administrator::Design: Enforce principle of least privilege::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
