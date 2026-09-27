# CAPEC-445 — Malicious Logic Insertion into Product Software via Configuration Management Manipulation

<a id="capec-445"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary exploits a configuration management system so that malicious logic is inserted into a software products build, update or deployed environment. If an adversary can control the elements included in a product's configuration management for build they can potentially replace, modify or insert code files containing malicious logic. If an adversary can control elements of a product's ongoin

## Mapped ATT&CK techniques (1)

- [T1195.001 — Compromise Software Dependencies and Development Tools](/mitre/techniques/T1195-001.md)

## Prerequisites

- Access to the configuration management system during deployment or currently deployed at a victim location. This access is often obtained via insider access or by leveraging another attack pattern t

## Mitigations

- Assess software during development and prior to deployment to ensure that it functions as intended and without any malicious functionality.
- Leverage anti-virus products to detect and quarantine software with known virus.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
