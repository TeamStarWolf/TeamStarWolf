# CAPEC-523 — Malicious Software Implanted

<a id="capec-523"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low

An attacker implants malicious software into the system in the supply chain distribution channel, with purpose of causing malicious disruption or allowing for additional compromise when the system is deployed.

## Mapped ATT&CK techniques (1)

- [T1195.002](/mitre/techniques/T1195-002.md)

**Prerequisites:** ::Physical access to the system after it has left the manufacturer but before it is deployed at the victim location.::

**Skills required:** ::SKILL:Advanced knowledge of the design of the system and it's operating system components and subcomponents.:LEVEL:High::SKILL:Malicious software cr

**Mitigations:** ::Deploy strong code integrity policies to allow only authorized apps to run.::Use endpoint detection and response solutions that can automaticalkly detect and remediate suspicious activities.::Maintain a highly secure build and update infrastructure


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
