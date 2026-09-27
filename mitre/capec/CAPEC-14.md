# CAPEC-14 — Client-side Injection-induced Buffer Overflow

<a id="capec-14"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

This type of attack exploits a buffer overflow vulnerability in targeted client software through injection of malicious content from a custom-built hostile service. This hostile service is created to deliver the correct content to the client software. For example, if the client-side application is a browser, the service will host a webpage that the browser loads.

## Related CWE (8)

- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-353 — Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
- [CWE-118 — Incorrect Access of Indexable Resource ('Range Error')](https://cwe.mitre.org/data/definitions/118.html)
- [CWE-119 — Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)

## Prerequisites

- The targeted client software communicates with an external server.
- The targeted client software has a buffer overflow vulnerability.

## Skills required

- To achieve a denial of service, an attacker can simply overflow a buffer by inserting a long string into an attacker-modifiable injection vect

## Mitigations

- The client software should not install untrusted code from a non-authenticated server.
- The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers.:

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
