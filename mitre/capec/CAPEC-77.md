# CAPEC-77 — Manipulating User-Controlled Variables

<a id="capec-77"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

This attack targets user controlled variables (DEBUG=1, PHP Globals, and So Forth). An adversary can override variables leveraging user-supplied, untrusted query variables directly used on the application server without any data sanitization. In extreme cases, the adversary can change variables controlling the business logic of the application. For instance, in languages like PHP, a number of poor

## Related CWE (7)

- [CWE-15 — External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)
- [CWE-94 — Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-96 — Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-302 — Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)
- [CWE-473 — PHP External Variable Modification](https://cwe.mitre.org/data/definitions/473.html)
- [CWE-1321 — Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')](https://cwe.mitre.org/data/definitions/1321.html)

## Prerequisites

- A variable consumed by the application server is exposed to the client.
- A variable consumed by the application server can be overwritten by the user.
- The application server trusts user supplied da

## Skills required

- The malicious user can easily try some well-known global variables and find one which matches.:LEVEL:Low
- The adversary can use automate

## Mitigations

- Do not allow override of global variables and do Not Trust Global Variables. If the register_globals option is enabled, PHP will create global variables for each GET, POST, and cookie variable included in the HTTP request. This means that a malicio

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
