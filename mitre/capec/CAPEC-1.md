# CAPEC-1 — Accessing Functionality Not Properly Constrained by ACLs

<a id="capec-1"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

In applications, particularly web applications, access to functionality is mitigated by an authorization framework. This framework maps Access Control Lists (ACLs) to elements of the application's functionality; particularly URL's for web apps. In the case that the administrator failed to specify an ACL for a particular element, an attacker may be able to access it with impunity. An attacker with the ability to access functionality not properly constrained by ACLs can obtain sensitive information and possibly compromise the entire application. Such an attacker can access resources that must be available only to users at a higher privilege level, can access management sections of the application, or can run queries for data that they otherwise not supposed to.

## Mapped ATT&CK techniques (1)

- [T1574.010 — Services File Permissions Weakness](/mitre/techniques/T1574-010.md) — Adversaries may execute their own malicious payloads by hijacking the binaries used by services.

## Related CWE (16)

- [CWE-276 — Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html) — During installation, installed file permissions are set to allow anyone to modify those files.
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) — The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-434 — Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html) — The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) — The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.
- [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html) — The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.
- [CWE-1191 — On-Chip Debug and Test Interface With Improper Access Control](https://cwe.mitre.org/data/definitions/1191.html) — The chip does not implement or does not correctly perform access control to check whether users are authorized to access internal registers and test modes through the physical debug/test interface.
- [CWE-1193 — Power-On of Untrusted Execution Core Before Enabling Fabric Access Control](https://cwe.mitre.org/data/definitions/1193.html) — The product enables components that contain untrusted firmware before memory and fabric access controls have been enabled.
- [CWE-1220 — Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html) — The product implements access controls via a policy or other feature with the intention to disable or restrict accesses (reads and/or writes) to assets in a system from untrusted agents.
- [CWE-1297 — Unprotected Confidential Information on Device is Accessible by OSAT Vendors](https://cwe.mitre.org/data/definitions/1297.html) — The product does not adequately protect confidential information on the device from being accessed by Outsourced Semiconductor Assembly and Test (OSAT) vendors.
- [CWE-1311 — Improper Translation of Security Attributes by Fabric Bridge](https://cwe.mitre.org/data/definitions/1311.html) — The bridge incorrectly translates security attributes from either trusted to untrusted or from untrusted to trusted when converting from one fabric protocol to another.
- [CWE-1314 — Missing Write Protection for Parametric Data Values](https://cwe.mitre.org/data/definitions/1314.html) — The device does not write-protect the parametric data values for sensors that scale the sensor value, allowing untrusted software to manipulate the apparent result and potentially damage hardware or cause operational failure.
- [CWE-1315 — Improper Setting of Bus Controlling Capability in Fabric End-point](https://cwe.mitre.org/data/definitions/1315.html) — The bus controller enables bits in the fabric end-point to allow responder devices to control transactions on the fabric.
- [CWE-1318 — Missing Support for Security Features in On-chip Fabrics or Buses](https://cwe.mitre.org/data/definitions/1318.html) — On-chip fabrics or buses either do not support or are not configured to support privilege separation or other security features, such as access control.
- [CWE-1320 — Improper Protection for Outbound Error Messages and Alert Signals](https://cwe.mitre.org/data/definitions/1320.html) — Untrusted agents can disable alerts about signal conditions exceeding limits or the response mechanism that handles such alerts.
- [CWE-1321 — Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')](https://cwe.mitre.org/data/definitions/1321.html) — The product receives input from an upstream component that specifies attributes that are to be initialized or updated in an object, but it does not properly control modifications of attributes of the object prototype.
- [CWE-1327 — Binding to an Unrestricted IP Address](https://cwe.mitre.org/data/definitions/1327.html) — The product assigns the address 0.0.0.0 for a database server, a cloud service/instance, or any computing resource that communicates remotely.

## Prerequisites

- The application must be navigable in a manner that associates elements (subsections) of the application with ACLs.
- The various resources, or individual URLs, must be somehow discoverable by the attacker
- The administrator must have forgotten to associate an ACL or has associated an inappropriately permissive ACL with a particular navigable resource.

## Skills required

- [Low] In order to discover unrestricted resources, the attacker does not need special tools or skills. They only have to observe the resources or access mechanisms invoked as each action is performed and then try and access those access mechanisms directly.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- In a J2EE setting, administrators can associate a role that is impossible for the authenticator to grant users, such as "NoAccess", with all Servlets to which access is guarded by a limited number of servlets visible to, and accessible by, the user. Having done so, any direct access to those protected Servlets will be prohibited by the web container. In a more general setting, the administrator must mark every resource besides the ones supposed to be exposed to the user as accessible by a role impossible for the user to assume. The default security setting must be to deny access and then grant access only to those resources intended by business logic.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
