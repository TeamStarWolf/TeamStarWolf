# CAPEC-524 — Rogue Integration Procedures

<a id="capec-524"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An attacker alters or establishes rogue processes in an integration facility in order to insert maliciously altered components into the system. The attacker would then supply the malicious components. This would allow for malicious disruption or additional compromise when the system is deployed.

## Prerequisites

- Physical access to an integration facility that prepares the system before it is deployed at the victim location.

## Skills required

- [High] Advanced knowledge of the design of the system.
- [High] Hardware creation and manufacture of replacement components.

## Mitigations

- Deploy strong code integrity policies to allow only authorized apps to run.
- Use endpoint detection and response solutions that can automaticalkly detect and remediate suspicious activities.
- Maintain a highly secure build and update infrastructure by immediately applying security patches for OS and software, implementing mandatory integrity controls to ensure only trusted tools run, and requiring multi-factor authentication for admins.
- Require SSL for update channels and implement certificate transparency based verification.
- Sign everything, including configuration files, XML files and packages.
- Develop an incident response process, disclose supply chain incidents and notify customers with accurate and timely information.
- Maintain strong physical system access controls and monitor networks and physical facilities for insider threats.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
