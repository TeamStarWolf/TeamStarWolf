# CAPEC-523 — Malicious Software Implanted

<a id="capec-523"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An attacker implants malicious software into the system in the supply chain distribution channel, with purpose of causing malicious disruption or allowing for additional compromise when the system is deployed.

## Mapped ATT&CK techniques (1)

- [T1195.002 — Compromise Software Supply Chain](/mitre/techniques/T1195-002.md) — Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- Physical access to the system after it has left the manufacturer but before it is deployed at the victim location.

## Skills required

- [High] Advanced knowledge of the design of the system and it's operating system components and subcomponents.
- [High] Malicious software creation.

## Mitigations

- Deploy strong code integrity policies to allow only authorized apps to run.
- Use endpoint detection and response solutions that can automaticalkly detect and remediate suspicious activities.
- Maintain a highly secure build and update infrastructure by immediately applying security patches for OS and software, implementing mandatory integrity controls to ensure only trusted tools run, and requiring multi-factor authentication for admins.
- Require SSL for update channels and implement certificate transparency based verification.
- Sign everything, including configuration files, XML files and packages.
- Develop an incident response process, disclose supply chain incidents and notify customers with accurate and timely information.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
