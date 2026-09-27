# CAPEC-580 — System Footprinting

<a id="capec-580"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Likelihood:** Low  
**Status:** Stable  

An adversary engages in active probing and exploration activities to determine security information about a remote target system. Often times adversaries will rely on remote applications that can be probed for system configurations.

## Mapped ATT&CK techniques (1)

- [T1082 — System Information Discovery](/mitre/techniques/T1082.md)

## Related CWE (3)

- [CWE-204 — Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html)
- [CWE-205 — Observable Behavioral Discrepancy](https://cwe.mitre.org/data/definitions/205.html)
- [CWE-208 — Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)

## Prerequisites

- The adversary must have logical access to the target network and system.

## Skills required

- The adversary needs to know basic linux commands.:LEVEL:Low

## Mitigations

- Keep patches up to date by installing weekly or daily if possible.
- Identify programs that may be used to acquire peripheral information and block them by using a software restriction policy or tools that restrict program execution by using a proce

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
