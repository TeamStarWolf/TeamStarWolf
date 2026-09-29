# CAPEC-37 — Retrieve Embedded Sensitive Data

<a id="capec-37"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

An attacker examines a target system to find sensitive data that has been embedded within it. This information can reveal confidential contents, such as account numbers or individual keys/credentials that can be used as an intermediate step in a larger attack.

## Mapped ATT&CK techniques (2)

- [T1005 — Data from Local System](/mitre/techniques/T1005.md) — Adversaries may search local system sources, such as file systems, configuration files, local databases, virtual machine files, or process memory, to find files of interest and sensitive data prior to Exfiltration.
- [T1552.004 — Private Keys](/mitre/techniques/T1552-004.md) — Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials.

## Related CWE (14)

- [CWE-226 — Sensitive Information in Resource Not Removed Before Reuse](https://cwe.mitre.org/data/definitions/226.html) — The product releases a resource such as memory or a file so that it can be made available for reuse, but it does not clear or zeroize the information contained in the resource before the product performs a critical state transition or makes the resource available for reuse by other entities.
- [CWE-311 — Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html) — The product does not encrypt sensitive or critical information before storage or transmission.
- [CWE-525 — Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html) — The web application does not use an appropriate caching policy that specifies the extent to which each web page and associated form fields should be cached.
- [CWE-312 — Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html) — The product stores sensitive information in cleartext within a resource that might be accessible to another control sphere.
- [CWE-314 — Cleartext Storage in the Registry](https://cwe.mitre.org/data/definitions/314.html) — The product stores sensitive information in cleartext in the registry.
- [CWE-315 — Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html) — The product stores sensitive information in cleartext in a cookie.
- [CWE-318 — Cleartext Storage of Sensitive Information in Executable](https://cwe.mitre.org/data/definitions/318.html) — The product stores sensitive information in cleartext in an executable.
- [CWE-1239 — Improper Zeroization of Hardware Register](https://cwe.mitre.org/data/definitions/1239.html) — The hardware product does not properly clear sensitive information from built-in registers when the user of the hardware block changes.
- [CWE-1258 — Exposure of Sensitive System Information Due to Uncleared Debug Information](https://cwe.mitre.org/data/definitions/1258.html) — The hardware does not fully clear security-sensitive values, such as keys and intermediate values in cryptographic operations, when debug mode is entered.
- [CWE-1266 — Improper Scrubbing of Sensitive Data from Decommissioned Device](https://cwe.mitre.org/data/definitions/1266.html) — The product does not properly provide a capability for the product administrator to remove sensitive data at the time the product is decommissioned.
- [CWE-1272 — Sensitive Information Uncleared Before Debug/Power State Transition](https://cwe.mitre.org/data/definitions/1272.html) — The product performs a power or debug state transition, but it does not clear sensitive information that should no longer be accessible due to changes to information access restrictions.
- [CWE-1278 — Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques](https://cwe.mitre.org/data/definitions/1278.html) — Information stored in hardware may be recovered by an attacker with the capability to capture and analyze images of the integrated circuit using techniques such as scanning electron microscopy.
- [CWE-1301 — Insufficient or Incomplete Data Removal within Hardware Component](https://cwe.mitre.org/data/definitions/1301.html) — The product's data removal process does not completely delete all data and potentially sensitive information within hardware components.
- [CWE-1330 — Remanent Data Readable after Memory Erase](https://cwe.mitre.org/data/definitions/1330.html) — Confidential information stored in memory circuits is readable or recoverable after being cleared or erased.

## Prerequisites

- In order to feasibly execute this type of attack, some valuable data must be present in client software.
- Additionally, this information must be unprotected, or protected in a flawed fashion, or through a mechanism that fails to resist reverse engineering, statistical, or other attack.

## Skills required

- [Medium] The attacker must possess knowledge of client code structure as well as ability to reverse-engineer or decompile it or probe it in other ways. This knowledge is specific to the technology and language used for the client distribution

## Consequences

- Confidentiality / Read Data
- Integrity / Modify Data
- Confidentiality, Access Control, Authorization / Gain Privileges

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
