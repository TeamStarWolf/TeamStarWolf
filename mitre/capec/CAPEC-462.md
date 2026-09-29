# CAPEC-462 — Cross-Domain Search Timing

<a id="capec-462"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An attacker initiates cross domain HTTP / GET requests and times the server responses. The timing of these responses may leak important information on what is happening on the server. Browser's same origin policy prevents the attacker from directly reading the server responses (in the absence of any other weaknesses), but does not prevent the attacker from timing the responses to requests that the attacker issued cross domain.

## Related CWE (3)

- [CWE-385 — Covert Timing Channel](https://cwe.mitre.org/data/definitions/385.html) — Covert timing channels convey information by modulating some aspect of system behavior over time, so that the program receiving the information can observe system behavior and infer protected information.
- [CWE-352 — Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html) — The web application does not, or cannot, sufficiently verify whether a request was intentionally provided by the user who sent the request, which could have originated from an unauthorized actor.
- [CWE-208 — Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html) — Two separate operations in a product require different amounts of time to complete, in a way that is observable to an actor and reveals security-relevant information about the state of the product, such as whether a particular operation was successful or not.

## Prerequisites

- Ability to issue GET / POST requests cross domainJava Script is enabled in the victim's browserThe victim has an active session with the site from which the attacker would like to receive informationThe victim's site does not protect search functionality with cross site request forgery (CSRF) protection

## Skills required

- [Low] Some knowledge of Java Script

## Consequences

- Confidentiality / Read Data

## Mitigations

- Design: The victim's site could protect all potentially sensitive functionality (e.g. search functions) with cross site request forgery (CSRF) protection and not perform any work on behalf of forged requests
- Design: The browser's security model could be fixed to not leak timing information for cross domain requests

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
