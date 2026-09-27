# CAPEC-107 — Cross Site Tracing

<a id="capec-107"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium

Cross Site Tracing (XST) enables an adversary to steal the victim's session cookie and possibly other authentication credentials transmitted in the header of the HTTP request when the victim's browser communicates to a destination system's web server.

## Related CWE (2)

[CWE-693](/CWE_REFERENCE.md) [CWE-648](/CWE_REFERENCE.md)

**Prerequisites:** ::HTTP TRACE is enabled on the web server::The destination system is susceptible to XSS or an adversary can leverage some other weakness to bypass the same origin policy::Scripting is enabled in the c

**Skills required:** ::SKILL:Understanding of the HTTP protocol and an ability to craft a malicious script:LEVEL:Medium::

**Mitigations:** ::Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default.::Patch web browser against known security origin policy bypass exploits.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
