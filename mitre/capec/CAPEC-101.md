# CAPEC-101 — Server Side Include (SSI) Injection

<a id="capec-101"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attacker can use Server Side Include (SSI) Injection to send code to a web application that then gets executed by the web server. Doing so enables the attacker to achieve similar results to Cross Site Scripting, viz., arbitrary code execution and information disclosure, albeit on a more limited scale, since the SSI directives are nowhere near as powerful as a full-fledged scripting language. No

## Related CWE (3)

- [CWE-97 — Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Prerequisites

- A web server that supports server side includes and has them enabled
- User controllable input that can carry include directives to the web server

## Skills required

- The attacker needs to be aware of SSI technology, determine the nature of injection and be able to craft input that results in the SSI directi

## Mitigations

- Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them
- All user controllable input must be appropriately sanitized before use in the application. Th

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
