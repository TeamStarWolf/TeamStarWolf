# CAPEC-170 — Web Application Fingerprinting

<a id="capec-170"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** High  
**Status:** Draft  

An attacker sends a series of probes to a web application in order to elicit version-dependent and type-dependent behavior that assists in identifying the target. An attacker could learn information such as software versions, error pages, and response headers, variations in implementations of the HTTP protocol, directory structures, and other similar information about the targeted service. This in

## Related CWE (1)

- [CWE-497 — Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

## Prerequisites

- Any web application can be fingerprinted. However, some configuration choices can limit the useful information an attacker may collect during a fingerprinting attack.

## Skills required

- Attacker knows how to send HTTP request, SQL query to a web application.:LEVEL:Low

## Mitigations

- Implementation: Obfuscate server fields of HTTP response.
- Implementation: Hide inner ordering of HTTP response header.
- Implementation: Customizing HTTP error codes such as 404 or 500.
- Implementation: Hide URL file extension.
- Implementation: Hid

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
