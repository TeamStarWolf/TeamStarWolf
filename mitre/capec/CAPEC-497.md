# CAPEC-497 — File Discovery

<a id="capec-497"></a>

**Abstraction:** Standard  
**Typical severity:** Very Low  
**Likelihood:** High

An adversary engages in probing and exploration activities to determine if common key files exists. Such files often contain configuration and security parameters of the targeted application, system or network. Using this knowledge may often pave the way for more damaging attacks.

## Mapped ATT&CK techniques (1)

- [T1083](/mitre/techniques/T1083.md)

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must know the location of these common key files.::

**Mitigations:** ::Leverage file protection mechanisms to render these files accessible only to authorized parties.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
