# CAPEC-634 — Probe Audio and Video Peripherals

<a id="capec-634"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Stable  

The adversary exploits the target system's audio and video functionalities through malware or scheduled tasks. The goal is to capture sensitive information about the target for financial, personal, political, or other gains which is accomplished by collecting communication data between two parties via the use of peripheral devices (e.g. microphones and webcams) or applications with audio and video capabilities (e.g. Skype) on a system.

## Mapped ATT&CK techniques (2)

- [T1123 — Audio Capture](/mitre/techniques/T1123.md) — An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive…
- [T1125 — Video Capture](/mitre/techniques/T1125.md) — An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information.

## Related CWE (1)

- [CWE-267 — Privilege Defined With Unsafe Actions](https://cwe.mitre.org/data/definitions/267.html) — A particular privilege, role, capability, or right can be used to perform unsafe actions that were not intended, even when it is assigned to the correct entity.

## Prerequisites

- Knowledge of the target device's or application’s vulnerabilities that can be capitalized on with malicious code. The adversary must be able to place the malicious code on the target device.

## Skills required

- [High] To deploy a hidden process or malware on the system to automatically collect audio and video data.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Prevent unknown code from executing on a system through the use of an allowlist policy.
- Patch installed applications as soon as new updates become available.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
