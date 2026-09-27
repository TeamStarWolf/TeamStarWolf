# CAPEC-468 — Generic Cross-Browser Cross-Domain Theft

<a id="capec-468"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

An attacker makes use of Cascading Style Sheets (CSS) injection to steal data cross domain from the victim's browser. The attack works by abusing the standards relating to loading of CSS: 1. Send cookies on any load of CSS (including cross-domain) 2. When parsing returned CSS ignore all data that does not make sense before a valid CSS descriptor is found by the CSS parser.

## Related CWE (4)

- [CWE-707 — Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html) — The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being read from an upstream component or sent to a downstream…
- [CWE-149 — Improper Neutralization of Quoting Syntax](https://cwe.mitre.org/data/definitions/149.html) — Quotes injected into a product can be used to compromise a system.
- [CWE-177 — Improper Handling of URL Encoding (Hex Encoding)](https://cwe.mitre.org/data/definitions/177.html) — The product does not properly handle when all or part of an input has been URL encoded.
- [CWE-838 — Inappropriate Encoding for Output Context](https://cwe.mitre.org/data/definitions/838.html) — The product uses or specifies an encoding when generating output to a downstream component, but the specified encoding is not the same as the encoding that is expected by the downstream component.

## Prerequisites

- No new lines can be present in the injected CSS stringProper HTML or URL escaping of the " and ' characters is not presentThe attacker has control of two injection points: pre-string and post-string

## Skills required

- [High] Ability to craft a CSS injection

## Mitigations

- Design: Prior to performing CSS parsing, require the CSS to start with well-formed CSS when it is a cross-domain load and the MIME type is broken. This is a browser level fix.
- Implementation: Perform proper HTML encoding and URL escaping

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
