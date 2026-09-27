# CAPEC-107 — Cross Site Tracing

<a id="capec-107"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium  
**Status:** Draft  

Cross Site Tracing (XST) enables an adversary to steal the victim's session cookie and possibly other authentication credentials transmitted in the header of the HTTP request when the victim's browser communicates to a destination system's web server.

## Related CWE (2)

- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [CWE-648 — Incorrect Use of Privileged APIs](https://cwe.mitre.org/data/definitions/648.html)

## Prerequisites

- HTTP TRACE is enabled on the web server
- The destination system is susceptible to XSS or an adversary can leverage some other weakness to bypass the same origin policy
- Scripting is enabled in the c

## Skills required

- Understanding of the HTTP protocol and an ability to craft a malicious script:LEVEL:Medium

## Mitigations

- Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default.
- Patch web browser against known security origin policy bypass exploits.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
