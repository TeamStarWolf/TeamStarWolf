# CAPEC-1 — Accessing Functionality Not Properly Constrained by ACLs

<a id="capec-1"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

In applications, particularly web applications, access to functionality is mitigated by an authorization framework. This framework maps Access Control Lists (ACLs) to elements of the application's functionality; particularly URL's for web apps. In the case that the administrator failed to specify an ACL for a particular element, an attacker may be able to access it with impunity. An attacker with

## Mapped ATT&CK techniques (1)

- [T1574.010](/mitre/techniques/T1574-010.md)

## Related CWE (16)

[CWE-276](/CWE_REFERENCE.md) [CWE-285](/CWE_REFERENCE.md) [CWE-434](/CWE_REFERENCE.md) [CWE-693](/CWE_REFERENCE.md) [CWE-732](/CWE_REFERENCE.md) [CWE-1191](/CWE_REFERENCE.md) [CWE-1193](/CWE_REFERENCE.md) [CWE-1220](/CWE_REFERENCE.md) [CWE-1297](/CWE_REFERENCE.md) [CWE-1311](/CWE_REFERENCE.md) [CWE-1314](/CWE_REFERENCE.md) [CWE-1315](/CWE_REFERENCE.md) [CWE-1318](/CWE_REFERENCE.md) [CWE-1320](/CWE_REFERENCE.md) [CWE-1321](/CWE_REFERENCE.md) [CWE-1327](/CWE_REFERENCE.md)

**Prerequisites:** ::The application must be navigable in a manner that associates elements (subsections) of the application with ACLs.::The various resources, or individual URLs, must be somehow discoverable by the att

**Skills required:** ::SKILL:In order to discover unrestricted resources, the attacker does not need special tools or skills. They only have to observe the resources or ac

**Mitigations:** ::In a J2EE setting, administrators can associate a role that is impossible for the authenticator to grant users, such as NoAccess, with all Servlets to which access is guarded by a limited number of servlets visible to, and accessible by, the user. 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
