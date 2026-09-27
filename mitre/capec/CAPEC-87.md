# CAPEC-87 — Forceful Browsing

<a id="capec-87"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attacker employs forceful browsing (direct URL entry) to access portions of a website that are otherwise unreachable. Usually, a front controller or similar design pattern is employed to protect access to portions of a web application. Forceful browsing enables an attacker to access information, perform privileged operations and otherwise reach sections of the web application that have been imp

## Related CWE (3)

- [CWE-425 — Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

## Prerequisites

- The forcibly browseable pages or accessible resources must be discoverable and improperly protected.

## Skills required

- Forcibly browseable pages can be discovered by using a number of automated tools. Doing the same manually is tedious but by no means difficult

## Mitigations

- Authenticate request to every resource. In addition, every page or resource must ensure that the request it is handling has been made in an authorized context.
- Forceful browsing can also be made difficult to a large extent by not hard-coding names

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
