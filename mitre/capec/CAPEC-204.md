# CAPEC-204: Lifting Sensitive Data Embedded in Cache

<a id="capec-204"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

An adversary examines a target application's cache, or a browser cache, for sensitive information. Many applications that communicate with remote entities or which perform intensive calculations utilize caches to improve efficiency. However, if the application computes or receives sensitive information and the cache is not appropriately protected, an attacker can browse the cache and retrieve this information. This can result in the disclosure of sensitive information.

## Mapped ATT&CK techniques (1)

- [T1005: Data from Local System](/mitre/techniques/T1005.md): Adversaries may search local system sources, such as file systems, configuration files, local databases, virtual machine files, or process memory, to find files of interest and sensitive data prior to Exfiltration.

## Related CWE (4)

- [CWE-524: Use of Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/524.html): The code uses a cache that contains sensitive information, but the cache can be read by an actor outside of the intended control sphere.
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html): The product does not encrypt sensitive or critical information before storage or transmission.
- [CWE-1239: Improper Zeroization of Hardware Register](https://cwe.mitre.org/data/definitions/1239.html): The hardware product does not properly clear sensitive information from built-in registers when the user of the hardware block changes.
- [CWE-1258: Exposure of Sensitive System Information Due to Uncleared Debug Information](https://cwe.mitre.org/data/definitions/1258.html): The hardware does not fully clear security-sensitive values, such as keys and intermediate values in cryptographic operations, when debug mode is entered.

## Prerequisites

- The target application must store sensitive information in a cache.
- The cache must be inadequately protected against attacker access.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
