# CAPEC-124 — Shared Resource Manipulation

<a id="capec-124"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Status:** Draft  

An adversary exploits a resource shared between multiple applications, an application pool or hardware pin multiplexing to affect behavior. Resources may be shared between multiple applications or between multiple threads of a single application. Resource sharing is usually accomplished through mutual access to a single memory location or multiplexed hardware pins. If an adversary can manipulate t

## Related CWE (2)

- [CWE-1189 — Improper Isolation of Shared Resources on System-on-a-Chip (SoC)](https://cwe.mitre.org/data/definitions/1189.html) — The System-On-a-Chip (SoC) does not properly isolate shared resources between trusted and untrusted agents.
- [CWE-1331 — Improper Isolation of Shared Resources in Network On Chip (NoC)](https://cwe.mitre.org/data/definitions/1331.html) — The Network On Chip (NoC) does not isolate or incorrectly isolates its on-chip-fabric and internal resources such that they are shared between trusted and untrusted agents, creating timing channels.

## Prerequisites

- The target applications, threads or functions must share resources between themselves.
- The adversary must be able to manipulate some piece of the shared resource either directly or indirectly and t

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
