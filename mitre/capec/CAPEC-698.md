# CAPEC-698 — Install Malicious Extension

<a id="capec-698"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary directly installs or tricks a user into installing a malicious extension into existing trusted software, with the goal of achieving a variety of negative technical impacts.

## Mapped ATT&CK techniques (2)

- [T1176 — Software Extensions](/mitre/techniques/T1176.md)
- [T1505.004 — IIS Components](/mitre/techniques/T1505-004.md)

## Related CWE (2)

- [CWE-507 — Trojan Horse](https://cwe.mitre.org/data/definitions/507.html)
- [CWE-829 — Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Prerequisites

- The adversary must craft malware based on the type of software and system(s) they intend to exploit.
- If the adversary intends to install the malicious extension themself, they must first compromise

## Skills required

- Ability to create malicious extensions that can exploit specific software applications and systems.:LEVEL:Medium
- Optional: Ability to e

## Mitigations

- Only install extensions/plugins from official/verifiable sources.
- Confirm extensions/plugins are legitimate and not malware masquerading as a legitimate extension/plugin.
- Ensure the underlying software leveraging the extension/plugin (including o

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
