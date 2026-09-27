# CAPEC-642 — Replace Binaries

<a id="capec-642"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** 

Adversaries know that certain binaries will be regularly executed as part of normal processing. If these binaries are not protected with the appropriate file system permissions, it could be possible to replace them with malware. This malware might be executed at higher system permission levels. A variation of this pattern is to discover self-extracting installation packages that unpack binaries to

## Mapped ATT&CK techniques (3)

- [T1505.005](/mitre/techniques/T1505-005.md)
- [T1554](/mitre/techniques/T1554.md)
- [T1574.005](/mitre/techniques/T1574-005.md)

## Related CWE (1)

[CWE-732](/CWE_REFERENCE.md)

**Prerequisites:** ::The attacker must be able to place the malicious binary on the target machine.::

**Mitigations:** ::Insure that binaries commonly used by the system have the correct file permissions. Set operating system policies that restrict privilege elevation of non-Administrators. Use auditing tools to observe changes to system services.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
