# CAPEC-149 — Explore for Predictable Temporary File Names

<a id="capec-149"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An attacker explores a target to identify the names and locations of predictable temporary files for the purpose of launching further attacks against the target. This involves analyzing naming conventions and storage locations of the temporary files created by a target application. If an attacker can predict the names of temporary files they can use this information to mount other attacks, such as

## Related CWE (1)

[CWE-377](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted application must create names for temporary files using a predictable procedure, e.g. using sequentially increasing numbers.::The attacker must be able to see the names of the files the


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
