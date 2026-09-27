# CAPEC-58 — Restful Privilege Elevation

<a id="capec-58"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

An adversary identifies a Rest HTTP (Get, Put, Delete) style permission method allowing them to perform various malicious actions upon server data due to lack of access control mechanisms implemented within the application service accepting HTTP messages.

## Related CWE (2)

[CWE-267](/CWE_REFERENCE.md) [CWE-269](/CWE_REFERENCE.md)

**Prerequisites:** ::The attacker needs to be able to identify HTTP Get URLs. The Get methods must be set to call applications that perform operations other than get such as update and delete.::

**Skills required:** ::SKILL:It is relatively straightforward to identify an HTTP Get method that changes state on the server side and executes against an over-privileged 

**Mitigations:** ::Design: Enforce principle of least privilege::Implementation: Ensure that HTTP Get methods only retrieve state and do not alter state on the server side::Implementation: Ensure that HTTP methods have proper ACLs based on what the functionality they


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
