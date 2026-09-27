# CAPEC-1 — Accessing Functionality Not Properly Constrained by ACLs

<a id="capec-1"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

In applications, particularly web applications, access to functionality is mitigated by an authorization framework. This framework maps Access Control Lists (ACLs) to elements of the application's functionality; particularly URL's for web apps. In the case that the administrator failed to specify an ACL for a particular element, an attacker may be able to access it with impunity. An attacker with

## Mapped ATT&CK techniques (1)

- [T1574.010 — Services File Permissions Weakness](/mitre/techniques/T1574-010.md)

## Related CWE (16)

- [CWE-276 — Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-434 — Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [CWE-1191 — On-Chip Debug and Test Interface With Improper Access Control](https://cwe.mitre.org/data/definitions/1191.html)
- [CWE-1193 — Power-On of Untrusted Execution Core Before Enabling Fabric Access Control](https://cwe.mitre.org/data/definitions/1193.html)
- [CWE-1220 — Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html)
- [CWE-1297 — Unprotected Confidential Information on Device is Accessible by OSAT Vendors](https://cwe.mitre.org/data/definitions/1297.html)
- [CWE-1311 — Improper Translation of Security Attributes by Fabric Bridge](https://cwe.mitre.org/data/definitions/1311.html)
- [CWE-1314 — Missing Write Protection for Parametric Data Values](https://cwe.mitre.org/data/definitions/1314.html)
- [CWE-1315 — Improper Setting of Bus Controlling Capability in Fabric End-point](https://cwe.mitre.org/data/definitions/1315.html)
- [CWE-1318 — Missing Support for Security Features in On-chip Fabrics or Buses](https://cwe.mitre.org/data/definitions/1318.html)
- [CWE-1320 — Improper Protection for Outbound Error Messages and Alert Signals](https://cwe.mitre.org/data/definitions/1320.html)
- [CWE-1321 — Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')](https://cwe.mitre.org/data/definitions/1321.html)
- [CWE-1327 — Binding to an Unrestricted IP Address](https://cwe.mitre.org/data/definitions/1327.html)

## Prerequisites

- The application must be navigable in a manner that associates elements (subsections) of the application with ACLs.
- The various resources, or individual URLs, must be somehow discoverable by the att

## Skills required

- In order to discover unrestricted resources, the attacker does not need special tools or skills. They only have to observe the resources or ac

## Mitigations

- In a J2EE setting, administrators can associate a role that is impossible for the authenticator to grant users, such as NoAccess, with all Servlets to which access is guarded by a limited number of servlets visible to, and accessible by, the user.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
