# CAPEC-637 — Collect Data from Clipboard

<a id="capec-637"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Low  
**Status:** Stable  

The adversary exploits an application that allows for the copying of sensitive data or information by collecting information copied to the clipboard. Data copied to the clipboard can be accessed by other applications, such as malware built to exfiltrate or log clipboard contents on a periodic basis. In this way, the adversary aims to garner information to which they are unauthorized.

## Mapped ATT&CK techniques (1)

- [T1115 — Clipboard Data](/mitre/techniques/T1115.md) — Adversaries may collect data stored in the clipboard from users copying information within or between applications.

## Related CWE (1)

- [CWE-267 — Privilege Defined With Unsafe Actions](https://cwe.mitre.org/data/definitions/267.html) — A particular privilege, role, capability, or right can be used to perform unsafe actions that were not intended, even when it is assigned to the correct entity.

## Prerequisites

- The adversary must have a means (i.e., a pre-installed tool or background process) by which to collect data from the clipboard and store it. That is, when the target copies data to the clipboard (e.

## Skills required

- To deploy a hidden process or malware on the system to automatically collect clipboard data.:LEVEL:High

## Mitigations

- While copying and pasting of data with the clipboard is a legitimate and practical function, certain situations and context may require the disabling of this feature. Just as certain applications disable screenshot capability, applications that han

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
