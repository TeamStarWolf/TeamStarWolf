# CAPEC-537 — Infiltration of Hardware Development Environment

<a id="capec-537"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary, leveraging the ability to manipulate components of primary support systems and tools within the development and production environments, inserts malicious software within the hardware and/or firmware development environment. The infiltration purpose is to alter developed hardware components in a system destined for deployment at the victim's organization, for the purpose of disruptio

## Mapped ATT&CK techniques (1)

- [T1195.003 — Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md)

## Prerequisites

- The victim must use email or removable media from systems running the IDE (or systems adjacent to the IDE systems).
- The victim must have a system running exploitable applications and/or a vulnerabl

## Skills required

- Intelligence about the manufacturer's operating environment and infrastructure.:LEVEL:Medium
- Ability to develop, deploy, and maintain a

## Mitigations

- Verify software downloads and updates to ensure they have not been modified be adversaries
- Leverage antivirus tools to detect known malware
- Do not download software from untrusted sources
- Educate designers, developers, engineers, etc. on social

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
