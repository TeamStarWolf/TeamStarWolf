# CAPEC-511 — Infiltration of Software Development Environment

<a id="capec-511"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An attacker uses common delivery mechanisms such as email attachments or removable media to infiltrate the IDE (Integrated Development Environment) of a victim manufacturer with the intent of implanting malware allowing for attack control of the victim IDE environment. The attack then uses this access to exfiltrate sensitive data or information, manipulate said data or information, and conceal the

## Mapped ATT&CK techniques (1)

- [T1195.001 — Compromise Software Dependencies and Development Tools](/mitre/techniques/T1195-001.md) — Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- The victim must use email or removable media from systems running the IDE (or systems adjacent to the IDE systems).
- The victim must have a system running exploitable applications and/or a vulnerabl

## Skills required

- Intelligence about the manufacturer's operating environment and infrastructure.:LEVEL:Medium
- Ability to develop, deploy, and maintain a

## Mitigations

- Avoid the common delivery mechanisms of adversaries, such as email attachments, which could introduce the malware.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
