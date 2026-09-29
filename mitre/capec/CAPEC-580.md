# CAPEC-580 — System Footprinting

<a id="capec-580"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Likelihood:** Low  
**Status:** Stable  

An adversary engages in active probing and exploration activities to determine security information about a remote target system. Often times adversaries will rely on remote applications that can be probed for system configurations.

## Mapped ATT&CK techniques (1)

- [T1082 — System Information Discovery](/mitre/techniques/T1082.md) — An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.

## Related CWE (3)

- [CWE-204 — Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html) — The product provides different responses to incoming requests in a way that reveals internal state information to an unauthorized actor outside of the intended control sphere.
- [CWE-205 — Observable Behavioral Discrepancy](https://cwe.mitre.org/data/definitions/205.html) — The product's behaviors indicate important differences that may be observed by unauthorized actors in a way that reveals (1) its internal state or decision process, or (2) differences from other products with equivalent functionality.
- [CWE-208 — Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html) — Two separate operations in a product require different amounts of time to complete, in a way that is observable to an actor and reveals security-relevant information about the state of the product, such as whether a particular operation was successful or not.

## Prerequisites

- The adversary must have logical access to the target network and system.

## Skills required

- [Low] The adversary needs to know basic linux commands.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Keep patches up to date by installing weekly or daily if possible.
- Identify programs that may be used to acquire peripheral information and block them by using a software restriction policy or tools that restrict program execution by using a process allowlist.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
