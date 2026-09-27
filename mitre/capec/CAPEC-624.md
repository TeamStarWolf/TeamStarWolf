# CAPEC-624 — Hardware Fault Injection

<a id="capec-624"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Stable  

The adversary uses disruptive signals or events, or alters the physical environment a device operates in, to cause faulty behavior in electronic devices. This can include electromagnetic pulses, laser pulses, clock glitches, ambient temperature extremes, and more. When performed in a controlled manner on devices performing cryptographic operations, this faulty behavior can be exploited to derive s

## Related CWE (8)

- [CWE-1247 — Improper Protection Against Voltage and Clock Glitches](https://cwe.mitre.org/data/definitions/1247.html)
- [CWE-1248 — Semiconductor Defects in Hardware Logic with Security-Sensitive Implications](https://cwe.mitre.org/data/definitions/1248.html)
- [CWE-1256 — Improper Restriction of Software Interfaces to Hardware Features](https://cwe.mitre.org/data/definitions/1256.html)
- [CWE-1319 — Improper Protection against Electromagnetic Fault Injection (EM-FI)](https://cwe.mitre.org/data/definitions/1319.html)
- [CWE-1332 — Improper Handling of Faults that Lead to Instruction Skips](https://cwe.mitre.org/data/definitions/1332.html)
- [CWE-1334 — Unauthorized Error Injection Can Degrade Hardware Redundancy](https://cwe.mitre.org/data/definitions/1334.html)
- [CWE-1338 — Improper Protections Against Hardware Overheating](https://cwe.mitre.org/data/definitions/1338.html)
- [CWE-1351 — Improper Handling of Hardware Behavior in Exceptionally Cold Environments](https://cwe.mitre.org/data/definitions/1351.html)

## Prerequisites

- Physical access to the system
- The adversary must be cognizant of where fault injection vulnerabilities exist in the system in order to leverage them for exploitation.

## Skills required

- Adversaries require non-trivial technical skills to create and implement fault injection attacks. Although this style of attack has become eas

## Mitigations

- Implement robust physical security countermeasures and monitoring.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
