# CAPEC-673 — Developer Signing Maliciously Altered Software

<a id="capec-673"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

Software produced by a reputable developer is clandestinely infected with malicious code and then digitally signed by the unsuspecting developer, where the software has been altered via a compromised software development or build process prior to being signed. The receiver or user of the software has no reason to believe that it is anything but legitimate and proceeds to deploy it to organizationa

## Mapped ATT&CK techniques (1)

- [T1195.002 — Compromise Software Supply Chain](/mitre/techniques/T1195-002.md)

## Prerequisites

- An adversary would need to have access to a targeted developer’s software development environment, including to their software build processes, where the adversary could ensure code maliciously tain

## Skills required

- The adversary must have the skills to infiltrate a developer’s software development/build environment and to implant malicious code in develop

## Mitigations

- Have a security concept of operations (CONOPS) for the IDE that includes: Protecting the IDE via logical isolation using firewall and DMZ technologies/architectures; Maintaining strict security administration and configuration management of configu

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
