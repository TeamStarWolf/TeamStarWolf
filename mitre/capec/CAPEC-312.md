# CAPEC-312 — Active OS Fingerprinting

<a id="capec-312"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Likelihood:** Medium  
**Status:** Stable  

An adversary engages in activity to detect the operating system or firmware version of a remote target by interrogating a device, server, or platform with a probe designed to solicit behavior that will reveal information about the operating systems or firmware in the environment. Operating System detection is possible because implementations of common protocols (Such as IP or TCP) differ in distin

## Mapped ATT&CK techniques (1)

- [T1082 — System Information Discovery](/mitre/techniques/T1082.md) — An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) — The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The ability to monitor and interact with network communications.Access to at least one host, and the privileges to interface with the network interface card.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
