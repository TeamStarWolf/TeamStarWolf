# CAPEC-462 — Cross-Domain Search Timing

<a id="capec-462"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An attacker initiates cross domain HTTP / GET requests and times the server responses. The timing of these responses may leak important information on what is happening on the server. Browser's same origin policy prevents the attacker from directly reading the server responses (in the absence of any other weaknesses), but does not prevent the attacker from timing the responses to requests that the

## Related CWE (3)

- [CWE-385 — Covert Timing Channel](https://cwe.mitre.org/data/definitions/385.html)
- [CWE-352 — Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
- [CWE-208 — Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)

## Prerequisites

- Ability to issue GET / POST requests cross domainJava Script is enabled in the victim's browserThe victim has an active session with the site from which the attacker would like to receive informatio

## Skills required

- Some knowledge of Java Script:LEVEL:Low

## Mitigations

- Design: The victim's site could protect all potentially sensitive functionality (e.g. search functions) with cross site request forgery (CSRF) protection and not perform any work on behalf of forged requests
- Design: The browser's security model co

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
