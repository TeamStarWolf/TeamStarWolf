# CAPEC-199 — XSS Using Alternate Syntax

<a id="capec-199"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An adversary uses alternate forms of keywords or commands that result in the same action as the primary form but which may not be caught by filters. For example, many keywords are processed in a case insensitive manner. If the site's web filtering algorithm does not convert all tags into a consistent case before the comparison with forbidden keywords it is possible to bypass filters (e.g., incompl

## Related CWE (1)

- [CWE-87 — Improper Neutralization of Alternate XSS Syntax](https://cwe.mitre.org/data/definitions/87.html) — The product does not neutralize or incorrectly neutralizes user-controlled input for alternate script syntax.

## Prerequisites

- Target client software must allow scripting such as JavaScript.

## Skills required

- To inject the malicious payload in a web page:LEVEL:Low
- To bypass non trivial filters in the application:LEVEL:High

## Mitigations

- Design: Use browser technologies that do not allow client side scripting.
- Design: Utilize strict type, character, and encoding enforcement
- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content s

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
