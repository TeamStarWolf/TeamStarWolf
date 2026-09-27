# CAPEC-313 — Passive OS Fingerprinting

<a id="capec-313"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Likelihood:** High  
**Status:** Stable  

An adversary engages in activity to detect the version or type of OS software in a an environment by passively monitoring communication between devices, nodes, or applications. Passive techniques for operating system detection send no actual probes to a target, but monitor network or client-server communication between nodes in order to identify operating systems based on observed behavior as comp

## Mapped ATT&CK techniques (1)

- [T1082 — System Information Discovery](/mitre/techniques/T1082.md)

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- The ability to monitor network communications.Access to at least one host, and the privileges to interface with the network interface card.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
