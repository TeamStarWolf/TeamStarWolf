# CAPEC-677 — Server Motherboard Compromise

<a id="capec-677"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

Malware is inserted in a server motherboard (e.g., in the flash memory) in order to alter server functionality from that intended. The development environment or hardware/software support activity environment is susceptible to an adversary inserting malicious software into hardware components during development or update.

## Mapped ATT&CK techniques (1)

- [T1195.003 — Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md) — Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- An adversary with access to hardware/software processes and tools within the development or hardware/software support environment can insert malicious software into hardware components during develo

## Mitigations

- Purchase IT systems, components and parts from government approved vendors whenever possible.
- Establish diversity among suppliers.
- Conduct rigorous threat assessments of suppliers.
- Require that Bills of Material (BoM) for critical parts and comp

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
