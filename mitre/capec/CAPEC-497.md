# CAPEC-497 — File Discovery

<a id="capec-497"></a>

**Abstraction:** Standard  
**Typical severity:** Very Low  
**Likelihood:** High  
**Status:** Draft  

An adversary engages in probing and exploration activities to determine if common key files exists. Such files often contain configuration and security parameters of the targeted application, system or network. Using this knowledge may often pave the way for more damaging attacks.

## Mapped ATT&CK techniques (1)

- [T1083 — File and Directory Discovery](/mitre/techniques/T1083.md) — Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) — The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The adversary must know the location of these common key files.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Leverage file protection mechanisms to render these files accessible only to authorized parties.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
