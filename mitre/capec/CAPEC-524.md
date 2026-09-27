# CAPEC-524 — Rogue Integration Procedures

<a id="capec-524"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low

An attacker alters or establishes rogue processes in an integration facility in order to insert maliciously altered components into the system. The attacker would then supply the malicious components. This would allow for malicious disruption or additional compromise when the system is deployed.

**Prerequisites:** ::Physical access to an integration facility that prepares the system before it is deployed at the victim location.::

**Skills required:** ::SKILL:Advanced knowledge of the design of the system.:LEVEL:High::SKILL:Hardware creation and manufacture of replacement components.:LEVEL:High::

**Mitigations:** ::Deploy strong code integrity policies to allow only authorized apps to run.::Use endpoint detection and response solutions that can automaticalkly detect and remediate suspicious activities.::Maintain a highly secure build and update infrastructure


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
