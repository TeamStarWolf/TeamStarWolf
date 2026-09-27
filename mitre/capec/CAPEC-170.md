# CAPEC-170 — Web Application Fingerprinting

<a id="capec-170"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** High  
**Status:** Draft  

An attacker sends a series of probes to a web application in order to elicit version-dependent and type-dependent behavior that assists in identifying the target. An attacker could learn information such as software versions, error pages, and response headers, variations in implementations of the HTTP protocol, directory structures, and other similar information about the targeted service. This information can then be used by an attacker to formulate a targeted attack plan. While web application fingerprinting is not intended to be damaging (although certain activities, such as network scans, can sometimes cause disruptions to vulnerable applications inadvertently) it may often pave the way for more damaging attacks.

## Related CWE (1)

- [CWE-497 — Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html) — The product does not properly prevent sensitive system-level information from being accessed by unauthorized actors who do not have the same level of access to the underlying system as the product does.

## Prerequisites

- Any web application can be fingerprinted. However, some configuration choices can limit the useful information an attacker may collect during a fingerprinting attack.

## Skills required

- [Low] Attacker knows how to send HTTP request, SQL query to a web application.

## Consequences

- Confidentiality / Other

## Mitigations

- Implementation: Obfuscate server fields of HTTP response.
- Implementation: Hide inner ordering of HTTP response header.
- Implementation: Customizing HTTP error codes such as 404 or 500.
- Implementation: Hide URL file extension.
- Implementation: Hide HTTP response header software information filed.
- Implementation: Hide cookie's software information filed.
- Implementation: Appropriately deal with error messages.
- Implementation: Obfuscate database type in Database API's error message.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
