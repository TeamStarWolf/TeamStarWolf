# CAPEC-537 — Infiltration of Hardware Development Environment

<a id="capec-537"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary, leveraging the ability to manipulate components of primary support systems and tools within the development and production environments, inserts malicious software within the hardware and/or firmware development environment. The infiltration purpose is to alter developed hardware components in a system destined for deployment at the victim's organization, for the purpose of disruption or further compromise.

## Mapped ATT&CK techniques (1)

- [T1195.003 — Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md) — Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- The victim must use email or removable media from systems running the IDE (or systems adjacent to the IDE systems).
- The victim must have a system running exploitable applications and/or a vulnerable configuration to allow for initial infiltration.
- The adversary must have working knowledge of some if not all of the components involved in the IDE system as well as the infrastructure.

## Skills required

- [Medium] Intelligence about the manufacturer's operating environment and infrastructure.
- [High] Ability to develop, deploy, and maintain a stealth malicious backdoor program remotely in what is essentially a hostile environment.
- [High] Development skills to construct malicious attachments that can be used to exploit vulnerabilities in typical desktop applications or system configurations. The malicious attachments should be crafted well enough to bypass typical defensive systems (IDS, anti-virus, etc)

## Mitigations

- Verify software downloads and updates to ensure they have not been modified be adversaries
- Leverage antivirus tools to detect known malware
- Do not download software from untrusted sources
- Educate designers, developers, engineers, etc. on social engineering attacks to avoid downloading malicious software via attacks such as phishing attacks

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
