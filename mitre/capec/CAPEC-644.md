# CAPEC-644 — Use of Captured Hashes (Pass The Hash)

<a id="capec-644"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary obtains (i.e. steals or purchases) legitimate Windows domain credential hash values to access systems within the domain that leverage the Lan Man (LM) and/or NT Lan Man (NTLM) authentication protocols.

## Mapped ATT&CK techniques (1)

- [T1550.002 — Pass the Hash](/mitre/techniques/T1550-002.md)

## Related CWE (5)

- [CWE-522 — Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-836 — Use of Password Hash Instead of Password for Authentication](https://cwe.mitre.org/data/definitions/836.html)
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [CWE-294 — Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)

## Prerequisites

- The system/application is connected to the Windows domain.
- The system/application leverages the Lan Man (LM) and/or NT Lan Man (NTLM) authentication protocols.
- The adversary possesses known Window

## Skills required

- Once an adversary obtains a known Windows credential hash value pair, leveraging it is trivial.:LEVEL:Low

## Mitigations

- Prevent the use of Lan Man and NT Lan Man authentication on severs and apply patch KB2871997 to Windows 7 and higher systems.
- Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the domain

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
