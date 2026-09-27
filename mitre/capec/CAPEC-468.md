# CAPEC-468 — Generic Cross-Browser Cross-Domain Theft

<a id="capec-468"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** 

An attacker makes use of Cascading Style Sheets (CSS) injection to steal data cross domain from the victim's browser. The attack works by abusing the standards relating to loading of CSS: 1. Send cookies on any load of CSS (including cross-domain) 2. When parsing returned CSS ignore all data that does not make sense before a valid CSS descriptor is found by the CSS parser.

## Related CWE (4)

[CWE-707](/CWE_REFERENCE.md) [CWE-149](/CWE_REFERENCE.md) [CWE-177](/CWE_REFERENCE.md) [CWE-838](/CWE_REFERENCE.md)

**Prerequisites:** ::No new lines can be present in the injected CSS stringProper HTML or URL escaping of the and ' characters is not presentThe attacker has control of two injection points: pre-string and post-string::

**Skills required:** ::SKILL:Ability to craft a CSS injection:LEVEL:High::

**Mitigations:** ::Design: Prior to performing CSS parsing, require the CSS to start with well-formed CSS when it is a cross-domain load and the MIME type is broken. This is a browser level fix.::Implementation: Perform proper HTML encoding and URL escaping::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
