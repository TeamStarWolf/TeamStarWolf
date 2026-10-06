# CAPEC-180: Exploiting Incorrectly Configured Access Control Security Levels

<a id="capec-180"></a>

Abstraction: Standard  
Typical severity: Medium  
Likelihood: High  
Status: Draft  

An attacker exploits a weakness in the configuration of access controls and is able to bypass the intended protection that these measures guard against and thereby obtain unauthorized access to the system or network. Sensitive functionality should always be protected with access controls. However configuring all but the most trivial access control systems can be very complicated and there are many opportunities for mistakes. If an attacker can learn of incorrectly configured access security settings, they may be able to exploit this in an attack.

## Mapped ATT&CK techniques (1)

- [T1574.010: Services File Permissions Weakness](/mitre/techniques/T1574-010.md): Adversaries may execute their own malicious payloads by hijacking the binaries used by services.

## Related CWE (13)

- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html): The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.
- [CWE-1190: DMA Device Enabled Too Early in Boot Phase](https://cwe.mitre.org/data/definitions/1190.html): The product enables a Direct Memory Access (DMA) capable device before the security configuration settings are established, which allows an attacker to extract data from or gain privileges on the product.
- [CWE-1191: On-Chip Debug and Test Interface With Improper Access Control](https://cwe.mitre.org/data/definitions/1191.html): The chip does not implement or does not correctly perform access control to check whether users are authorized to access internal registers and test modes through the physical debug/test interface.
- [CWE-1193: Power-On of Untrusted Execution Core Before Enabling Fabric Access Control](https://cwe.mitre.org/data/definitions/1193.html): The product enables components that contain untrusted firmware before memory and fabric access controls have been enabled.
- [CWE-1220: Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html): The product implements access controls via a policy or other feature with the intention to disable or restrict accesses (reads and/or writes) to assets in a system from untrusted agents.
- [CWE-1268: Policy Privileges are not Assigned Consistently Between Control and Data Agents](https://cwe.mitre.org/data/definitions/1268.html): The product's hardware-enforced access control for a particular resource improperly accounts for privilege discrepancies between control and write policies.
- [CWE-1280: Access Control Check Implemented After Asset is Accessed](https://cwe.mitre.org/data/definitions/1280.html): A product's hardware-based access control check occurs after the asset has been accessed.
- [CWE-1297: Unprotected Confidential Information on Device is Accessible by OSAT Vendors](https://cwe.mitre.org/data/definitions/1297.html): The product does not adequately protect confidential information on the device from being accessed by Outsourced Semiconductor Assembly and Test (OSAT) vendors.
- [CWE-1311: Improper Translation of Security Attributes by Fabric Bridge](https://cwe.mitre.org/data/definitions/1311.html): The bridge incorrectly translates security attributes from either trusted to untrusted or from untrusted to trusted when converting from one fabric protocol to another.
- [CWE-1315: Improper Setting of Bus Controlling Capability in Fabric End-point](https://cwe.mitre.org/data/definitions/1315.html): The bus controller enables bits in the fabric end-point to allow responder devices to control transactions on the fabric.
- [CWE-1318: Missing Support for Security Features in On-chip Fabrics or Buses](https://cwe.mitre.org/data/definitions/1318.html): On-chip fabrics or buses either do not support or are not configured to support privilege separation or other security features, such as access control.
- [CWE-1320: Improper Protection for Outbound Error Messages and Alert Signals](https://cwe.mitre.org/data/definitions/1320.html): Untrusted agents can disable alerts about signal conditions exceeding limits or the response mechanism that handles such alerts.
- [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')](https://cwe.mitre.org/data/definitions/1321.html): The product receives input from an upstream component that specifies attributes that are to be initialized or updated in an object, but it does not properly control modifications of attributes of the object prototype.

## Prerequisites

- The target must apply access controls, but incorrectly configure them. However, not all incorrect configurations can be exploited by an attacker. If the incorrect configuration applies too little security to some functionality, then the attacker may be able to exploit it if the access control would be the only thing preventing an attacker's access and it no longer does so. If the incorrect configuration applies too much security, it must prevent legitimate activity and the attacker must be able to force others to require this activity..

## Skills required

- [Low] In order to discover unrestricted resources, the attacker does not need special tools or skills. They only have to observe the resources or access mechanisms invoked as each action is performed and then try and access those access mechanisms directly.

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Authorization / Execute Unauthorized Commands
- Authorization / Gain Privileges
- Access Control, Authorization / Bypass Protection Mechanism
- Availability / Unreliable Execution

## Mitigations

- Design: Configure the access control correctly.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
