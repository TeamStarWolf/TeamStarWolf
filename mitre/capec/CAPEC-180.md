# CAPEC-180 — Exploiting Incorrectly Configured Access Control Security Levels

<a id="capec-180"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** High  
**Status:** Draft  

An attacker exploits a weakness in the configuration of access controls and is able to bypass the intended protection that these measures guard against and thereby obtain unauthorized access to the system or network. Sensitive functionality should always be protected with access controls. However configuring all but the most trivial access control systems can be very complicated and there are many

## Mapped ATT&CK techniques (1)

- [T1574.010 — Services File Permissions Weakness](/mitre/techniques/T1574-010.md)

## Related CWE (13)

- [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [CWE-1190 — DMA Device Enabled Too Early in Boot Phase](https://cwe.mitre.org/data/definitions/1190.html)
- [CWE-1191 — On-Chip Debug and Test Interface With Improper Access Control](https://cwe.mitre.org/data/definitions/1191.html)
- [CWE-1193 — Power-On of Untrusted Execution Core Before Enabling Fabric Access Control](https://cwe.mitre.org/data/definitions/1193.html)
- [CWE-1220 — Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html)
- [CWE-1268 — Policy Privileges are not Assigned Consistently Between Control and Data Agents](https://cwe.mitre.org/data/definitions/1268.html)
- [CWE-1280 — Access Control Check Implemented After Asset is Accessed](https://cwe.mitre.org/data/definitions/1280.html)
- [CWE-1297 — Unprotected Confidential Information on Device is Accessible by OSAT Vendors](https://cwe.mitre.org/data/definitions/1297.html)
- [CWE-1311 — Improper Translation of Security Attributes by Fabric Bridge](https://cwe.mitre.org/data/definitions/1311.html)
- [CWE-1315 — Improper Setting of Bus Controlling Capability in Fabric End-point](https://cwe.mitre.org/data/definitions/1315.html)
- [CWE-1318 — Missing Support for Security Features in On-chip Fabrics or Buses](https://cwe.mitre.org/data/definitions/1318.html)
- [CWE-1320 — Improper Protection for Outbound Error Messages and Alert Signals](https://cwe.mitre.org/data/definitions/1320.html)
- [CWE-1321 — Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')](https://cwe.mitre.org/data/definitions/1321.html)

## Prerequisites

- The target must apply access controls, but incorrectly configure them. However, not all incorrect configurations can be exploited by an attacker. If the incorrect configuration applies too little se

## Skills required

- In order to discover unrestricted resources, the attacker does not need special tools or skills. They only have to observe the resources or ac

## Mitigations

- Design: Configure the access control correctly.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
