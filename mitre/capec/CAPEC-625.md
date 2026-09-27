# CAPEC-625 — Mobile Device Fault Injection

<a id="capec-625"></a>

**Abstraction:** Standard  
**Status:** Draft  

Fault injection attacks against mobile devices use disruptive signals or events (e.g. electromagnetic pulses, laser pulses, clock glitches, etc.) to cause faulty behavior. When performed in a controlled manner on devices performing cryptographic operations, this faulty behavior can be exploited to derive secret key information. Although this attack usually requires physical control of the mobile device, it is non-destructive, and the device can be used after the attack without any indication that secret keys were compromised.

## Related CWE (8)

- [CWE-1247 — Improper Protection Against Voltage and Clock Glitches](https://cwe.mitre.org/data/definitions/1247.html) — The device does not contain or contains incorrectly implemented circuitry or sensors to detect and mitigate voltage and clock glitches and protect sensitive information or software contained on the device.
- [CWE-1248 — Semiconductor Defects in Hardware Logic with Security-Sensitive Implications](https://cwe.mitre.org/data/definitions/1248.html) — The security-sensitive hardware module contains semiconductor defects.
- [CWE-1256 — Improper Restriction of Software Interfaces to Hardware Features](https://cwe.mitre.org/data/definitions/1256.html) — The product provides software-controllable device functionality for capabilities such as power and clock management, but it does not properly limit functionality that can lead to modification of hardware memory or…
- [CWE-1319 — Improper Protection against Electromagnetic Fault Injection (EM-FI)](https://cwe.mitre.org/data/definitions/1319.html) — The device is susceptible to electromagnetic fault injection attacks, causing device internal information to be compromised or security mechanisms to be bypassed.
- [CWE-1332 — Improper Handling of Faults that Lead to Instruction Skips](https://cwe.mitre.org/data/definitions/1332.html) — The device is missing or incorrectly implements circuitry or sensors that detect and mitigate the skipping of security-critical CPU instructions when they occur.
- [CWE-1334 — Unauthorized Error Injection Can Degrade Hardware Redundancy](https://cwe.mitre.org/data/definitions/1334.html) — An unauthorized agent can inject errors into a redundant block to deprive the system of redundancy or put the system in a degraded operating mode.
- [CWE-1338 — Improper Protections Against Hardware Overheating](https://cwe.mitre.org/data/definitions/1338.html) — A hardware device is missing or has inadequate protection features to prevent overheating.
- [CWE-1351 — Improper Handling of Hardware Behavior in Exceptionally Cold Environments](https://cwe.mitre.org/data/definitions/1351.html) — A hardware device, or the firmware running on it, is missing or has incorrect protection features to maintain goals of security primitives when the device is cooled below standard operating temperatures.

## Skills required

- [High] Adversaries require non-trivial technical skills to create and implement fault injection attacks on mobile devices. Although this style of attack has become easier (commercial equipment and training classes are available to perform these attacks), they usual require significant setup and experimentation time during which physical access to the device is required. This prerequisite makes the attack challenging to perform (assuming that physical security countermeasures and monitoring are in place).

## Consequences

- Confidentiality, Access Control / Read Data

## Mitigations

- Strong physical security of all devices that contain secret key information. (even when devices are not in use)
- Frequent changes to secret keys and certificates.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
