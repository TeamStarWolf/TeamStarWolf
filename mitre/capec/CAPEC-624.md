# CAPEC-624: Hardware Fault Injection

<a id="capec-624"></a>

Abstraction: Meta  
Typical severity: High  
Likelihood: Low  
Status: Stable  

The adversary uses disruptive signals or events, or alters the physical environment a device operates in, to cause faulty behavior in electronic devices. This can include electromagnetic pulses, laser pulses, clock glitches, ambient temperature extremes, and more. When performed in a controlled manner on devices performing cryptographic operations, this faulty behavior can be exploited to derive secret key information.

## Related CWE (8)

- [CWE-1247: Improper Protection Against Voltage and Clock Glitches](https://cwe.mitre.org/data/definitions/1247.html): The device does not contain or contains incorrectly implemented circuitry or sensors to detect and mitigate voltage and clock glitches and protect sensitive information or software contained on the device.
- [CWE-1248: Semiconductor Defects in Hardware Logic with Security-Sensitive Implications](https://cwe.mitre.org/data/definitions/1248.html): The security-sensitive hardware module contains semiconductor defects.
- [CWE-1256: Improper Restriction of Software Interfaces to Hardware Features](https://cwe.mitre.org/data/definitions/1256.html): The product provides software-controllable device functionality for capabilities such as power and clock management, but it does not properly limit functionality that can lead to modification of hardware memory or register bits, or the ability to observe physical side channels.
- [CWE-1319: Improper Protection against Electromagnetic Fault Injection (EM-FI)](https://cwe.mitre.org/data/definitions/1319.html): The device is susceptible to electromagnetic fault injection attacks, causing device internal information to be compromised or security mechanisms to be bypassed.
- [CWE-1332: Improper Handling of Faults that Lead to Instruction Skips](https://cwe.mitre.org/data/definitions/1332.html): The device is missing or incorrectly implements circuitry or sensors that detect and mitigate the skipping of security-critical CPU instructions when they occur.
- [CWE-1334: Unauthorized Error Injection Can Degrade Hardware Redundancy](https://cwe.mitre.org/data/definitions/1334.html): An unauthorized agent can inject errors into a redundant block to deprive the system of redundancy or put the system in a degraded operating mode.
- [CWE-1338: Improper Protections Against Hardware Overheating](https://cwe.mitre.org/data/definitions/1338.html): A hardware device is missing or has inadequate protection features to prevent overheating.
- [CWE-1351: Improper Handling of Hardware Behavior in Exceptionally Cold Environments](https://cwe.mitre.org/data/definitions/1351.html): A hardware device, or the firmware running on it, is missing or has incorrect protection features to maintain goals of security primitives when the device is cooled below standard operating temperatures.

## Prerequisites

- Physical access to the system
- The adversary must be cognizant of where fault injection vulnerabilities exist in the system in order to leverage them for exploitation.

## Skills required

- [High] Adversaries require non-trivial technical skills to create and implement fault injection attacks. Although this style of attack has become easier (commercial equipment and training classes are available to perform these attacks), they usual require significant setup and experimentation time during which physical access to the device is required.

## Consequences

- Confidentiality / Read Data, Bypass Protection Mechanism, Hide Activities
- Integrity / Execute Unauthorized Commands

## Mitigations

- Implement robust physical security countermeasures and monitoring.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
