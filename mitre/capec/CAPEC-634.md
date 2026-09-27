# CAPEC-634 — Probe Audio and Video Peripherals

<a id="capec-634"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

The adversary exploits the target system's audio and video functionalities through malware or scheduled tasks. The goal is to capture sensitive information about the target for financial, personal, political, or other gains which is accomplished by collecting communication data between two parties via the use of peripheral devices (e.g. microphones and webcams) or applications with audio and video

## Mapped ATT&CK techniques (2)

- [T1123](/mitre/techniques/T1123.md)
- [T1125](/mitre/techniques/T1125.md)

## Related CWE (1)

[CWE-267](/CWE_REFERENCE.md)

**Prerequisites:** ::Knowledge of the target device's or application’s vulnerabilities that can be capitalized on with malicious code. The adversary must be able to place the malicious code on the target device.::

**Skills required:** ::SKILL:To deploy a hidden process or malware on the system to automatically collect audio and video data.:LEVEL:High::

**Mitigations:** ::Prevent unknown code from executing on a system through the use of an allowlist policy.::Patch installed applications as soon as new updates become available.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
