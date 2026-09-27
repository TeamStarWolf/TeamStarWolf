# CAPEC-576 — Group Permission Footprinting

<a id="capec-576"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Likelihood:** Low

An adversary exploits functionality meant to identify information about user groups and their permissions on the target system to an authorized user. By knowing what users/permissions are registered on the target system, the adversary can inform further and more targeted malicious behavior. An example Windows command which can list local groups is net localgroup.

## Mapped ATT&CK techniques (2)

- [T1069](/mitre/techniques/T1069.md)
- [T1615](/mitre/techniques/T1615.md)

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must have gained access to the target system via physical or logical means in order to carry out this attack.::

**Mitigations:** ::Identify programs (such as net) that may be used to enumerate local group permissions and block them by using a software restriction Policy or tools that restrict program execution by using a process allowlist.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
