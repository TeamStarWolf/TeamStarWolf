# CAPEC-532 — Altered Installed BIOS

<a id="capec-532"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Stable  

An attacker with access to download and update system software sends a maliciously altered BIOS to the victim or victim supplier/integrator, which when installed allows for future exploitation.

## Mapped ATT&CK techniques (2)

- [T1495 — Firmware Corruption](/mitre/techniques/T1495.md)
- [T1542.001 — System Firmware](/mitre/techniques/T1542-001.md)

## Prerequisites

- Advanced knowledge about the installed target system design.
- Advanced knowledge about the download and update installation processes.
- Access to the download and update system(s) used to deliver BI

## Skills required

- Able to develop a malicious BIOS image with the original functionality as a normal BIOS image, but with added functionality that allows for la

## Mitigations

- Deploy strong code integrity policies to allow only authorized apps to run.
- Use endpoint detection and response solutions that can automaticalkly detect and remediate suspicious activities.
- Maintain a highly secure build and update infrastructure

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
