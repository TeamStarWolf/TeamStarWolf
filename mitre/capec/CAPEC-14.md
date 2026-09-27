# CAPEC-14 — Client-side Injection-induced Buffer Overflow

<a id="capec-14"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

This type of attack exploits a buffer overflow vulnerability in targeted client software through injection of malicious content from a custom-built hostile service. This hostile service is created to deliver the correct content to the client software. For example, if the client-side application is a browser, the service will host a webpage that the browser loads.

## Related CWE (8)

[CWE-120](/CWE_REFERENCE.md) [CWE-353](/CWE_REFERENCE.md) [CWE-118](/CWE_REFERENCE.md) [CWE-119](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-680](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted client software communicates with an external server.::The targeted client software has a buffer overflow vulnerability.::

**Skills required:** ::SKILL:To achieve a denial of service, an attacker can simply overflow a buffer by inserting a long string into an attacker-modifiable injection vect

**Mitigations:** ::The client software should not install untrusted code from a non-authenticated server.::The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers.:


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
