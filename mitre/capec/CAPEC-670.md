# CAPEC-670 — Software Development Tools Maliciously Altered

<a id="capec-670"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary with the ability to alter tools used in a development environment causes software to be developed with maliciously modified tools. Such tools include requirements management and database tools, software design tools, configuration management tools, compilers, system build tools, and software performance testing and load testing tools. The adversary then carries out malicious acts once

## Mapped ATT&CK techniques (2)

- [T1127 — Trusted Developer Utilities Proxy Execution](/mitre/techniques/T1127.md) — Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads.
- [T1195.001 — Compromise Software Dependencies and Development Tools](/mitre/techniques/T1195-001.md) — Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- An adversary would need to have access to a targeted developer’s development environment and in particular to tools used to design, create, test and manage software, where the adversary could ensure

## Skills required

- Ability to leverage common delivery mechanisms (e.g., email attachments, removable media) to infiltrate a development environment to gain acce

## Mitigations

- Have a security concept of operations (CONOPS) for the development environment that includes: Maintaining strict security administration and configuration management of requirements management and database tools, software design tools, configuratio

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
