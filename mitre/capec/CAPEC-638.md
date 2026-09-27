# CAPEC-638 — Altered Component Firmware

<a id="capec-638"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Low  
**Status:** Stable  

An adversary exploits systems features and/or improperly protected firmware of hardware components, such as Hard Disk Drives (HDD), with the goal of executing malicious code from within the component's Master Boot Record (MBR). Conducting this type of attack entails the adversary infecting the target with firmware altering malware, using known tools, and a payload. Once this malware is executed, t

## Mapped ATT&CK techniques (1)

- [T1542.002 — Component Firmware](/mitre/techniques/T1542-002.md) — Adversaries may modify component firmware to persist on systems.

## Prerequisites

- Advanced knowledge about the target component's firmware
- Advanced knowledge about Master Boot Records (MBR)
- Advanced knowledge about tools used to insert firmware altering malware.
- Advanced knowl

## Skills required

- Ability to access and reverse engineer hardware component firmware.:LEVEL:High
- Ability to intercept components in transit.:LEVEL:High

## Mitigations

- Leverage hardware components known to not be susceptible to these types of attacks.
- Implement hardware RAID infrastructure.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
