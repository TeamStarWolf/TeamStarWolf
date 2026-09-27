# CAPEC-142 — DNS Cache Poisoning

<a id="capec-142"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

A domain name server translates a domain name (such as www.example.com) into an IP address that Internet hosts use to contact Internet resources. An adversary modifies a public DNS cache to cause certain names to resolve to incorrect addresses that the adversary specifies. The result is that client applications that rely upon the targeted cache for domain name resolution will be directed not to th

## Mapped ATT&CK techniques (1)

- [T1584.002](/mitre/techniques/T1584-002.md)

## Related CWE (5)

[CWE-348](/CWE_REFERENCE.md) [CWE-345](/CWE_REFERENCE.md) [CWE-349](/CWE_REFERENCE.md) [CWE-346](/CWE_REFERENCE.md) [CWE-350](/CWE_REFERENCE.md)

**Prerequisites:** ::A DNS cache must be vulnerable to some attack that allows the adversary to replace addresses in its lookup table.Client applications must trust the corrupted cashed values and utilize them for their

**Skills required:** ::SKILL:To overwrite/modify targeted DNS cache:LEVEL:Medium::

**Mitigations:** ::Configuration: Make sure your DNS servers have been updated to the latest versions::Configuration: UNIX services like rlogin, rsh/rcp, xhost, and nfs are all susceptible to wrong information being held in a cache. Care should be taken with these se


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
