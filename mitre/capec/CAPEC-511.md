# CAPEC-511 — Infiltration of Software Development Environment

<a id="capec-511"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An attacker uses common delivery mechanisms such as email attachments or removable media to infiltrate the IDE (Integrated Development Environment) of a victim manufacturer with the intent of implanting malware allowing for attack control of the victim IDE environment. The attack then uses this access to exfiltrate sensitive data or information, manipulate said data or information, and conceal these actions. This will allow and aid the attack to meet the goal of future compromise of a recipient of the victim's manufactured product further down in the supply chain.

## Mapped ATT&CK techniques (1)

- [T1195.001 — Compromise Software Dependencies and Development Tools](/mitre/techniques/T1195-001.md) — Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- The victim must use email or removable media from systems running the IDE (or systems adjacent to the IDE systems).
- The victim must have a system running exploitable applications and/or a vulnerable configuration to allow for initial infiltration.
- The attacker must have working knowledge of some if not all of the components involved in the IDE system as well as the infrastructure.

## Skills required

- [Medium] Intelligence about the manufacturer's operating environment and infrastructure.
- [High] Ability to develop, deploy, and maintain a stealth malicious backdoor program remotely in what is essentially a hostile environment.
- [High] Development skills to construct malicious attachments that can be used to exploit vulnerabilities in typical desktop applications or system configurations. The malicious attachments should be crafted well enough to bypass typical defensive systems (IDS, anti-virus, etc)

## Mitigations

- Avoid the common delivery mechanisms of adversaries, such as email attachments, which could introduce the malware.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
