# CAPEC-85 — AJAX Footprinting

<a id="capec-85"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** High  
**Status:** Draft  

This attack utilizes the frequent client-server roundtrips in Ajax conversation to scan a system. While Ajax does not open up new vulnerabilities per se, it does optimize them from an attacker point of view. A common first step for an attacker is to footprint the target environment to understand what attacks will work. Since footprinting relies on enumeration, the conversational pattern of rapid,

## Related CWE (9)

- [CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-113 — Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)
- [CWE-348 — Use of Less Trusted Source](https://cwe.mitre.org/data/definitions/348.html)
- [CWE-96 — Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-116 — Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
- [CWE-184 — Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)
- [CWE-86 — Improper Neutralization of Invalid Characters in Identifiers in Web Pages](https://cwe.mitre.org/data/definitions/86.html)
- [CWE-692 — Incomplete Denylist to Cross-Site Scripting](https://cwe.mitre.org/data/definitions/692.html)

## Prerequisites

- The user must allow JavaScript to execute in their browser

## Skills required

- To land and launch a script on victim's machine with appropriate footprinting logic for enumerating services and vulnerabilities in JavaScript

## Mitigations

- Design: Use browser technologies that do not allow client side scripting.
- Implementation: Perform input validation for all remote content.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
