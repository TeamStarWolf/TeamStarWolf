# CAPEC-625 — Mobile Device Fault Injection

<a id="capec-625"></a>

**Abstraction:** Standard  
**Status:** Draft  

Fault injection attacks against mobile devices use disruptive signals or events (e.g. electromagnetic pulses, laser pulses, clock glitches, etc.) to cause faulty behavior. When performed in a controlled manner on devices performing cryptographic operations, this faulty behavior can be exploited to derive secret key information. Although this attack usually requires physical control of the mobile d

## Related CWE (8)

- [CWE-1247 — Improper Protection Against Voltage and Clock Glitches](https://cwe.mitre.org/data/definitions/1247.html)
- [CWE-1248 — Semiconductor Defects in Hardware Logic with Security-Sensitive Implications](https://cwe.mitre.org/data/definitions/1248.html)
- [CWE-1256 — Improper Restriction of Software Interfaces to Hardware Features](https://cwe.mitre.org/data/definitions/1256.html)
- [CWE-1319 — Improper Protection against Electromagnetic Fault Injection (EM-FI)](https://cwe.mitre.org/data/definitions/1319.html)
- [CWE-1332 — Improper Handling of Faults that Lead to Instruction Skips](https://cwe.mitre.org/data/definitions/1332.html)
- [CWE-1334 — Unauthorized Error Injection Can Degrade Hardware Redundancy](https://cwe.mitre.org/data/definitions/1334.html)
- [CWE-1338 — Improper Protections Against Hardware Overheating](https://cwe.mitre.org/data/definitions/1338.html)
- [CWE-1351 — Improper Handling of Hardware Behavior in Exceptionally Cold Environments](https://cwe.mitre.org/data/definitions/1351.html)

## Skills required

- Adversaries require non-trivial technical skills to create and implement fault injection attacks on mobile devices. Although this style of att

## Mitigations

- Strong physical security of all devices that contain secret key information. (even when devices are not in use)
- Frequent changes to secret keys and certificates.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
