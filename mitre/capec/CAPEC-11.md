# CAPEC-11 — Cause Web Server Misclassification

<a id="capec-11"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An attack of this type exploits a Web server's decision to take action based on filename or file extension. Because different file types are handled by different server processes, misclassification may force the Web server to take unexpected action, or expected actions in an unexpected sequence. This may cause the server to exhaust resources, supply debug or system data to the attacker, or bind an

## Mapped ATT&CK techniques (1)

- [T1036.006 — Space after Filename](/mitre/techniques/T1036-006.md)

## Related CWE (1)

- [CWE-430 — Deployment of Wrong Handler](https://cwe.mitre.org/data/definitions/430.html)

## Prerequisites

- Web server software must rely on file name or file extension for processing.
- The attacker must be able to make HTTP requests to the web server.

## Skills required

- To modify file name or file extension:LEVEL:Low
- To use misclassification to force the Web server to disclose configuration information,

## Mitigations

- Implementation: Server routines should be determined by content not determined by filename or file extension.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
