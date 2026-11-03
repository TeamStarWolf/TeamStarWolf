# CAPEC-468: Generic Cross-Browser Cross-Domain Theft

<a id="capec-468"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

An attacker makes use of Cascading Style Sheets (CSS) injection to steal data cross domain from the victim's browser. The attack works by abusing the standards relating to loading of CSS: 1. Send cookies on any load of CSS (including cross-domain) 2. When parsing returned CSS ignore all data that does not make sense before a valid CSS descriptor is found by the CSS parser.

## Related CWE (4)

- [CWE-707: Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html): The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being used when received from an upstream component, or before being sent to a downstream component.
- [CWE-149: Improper Neutralization of Quoting Syntax](https://cwe.mitre.org/data/definitions/149.html): Quotes injected into a product can be used to compromise a system.
- [CWE-177: Improper Handling of URL Encoding (Hex Encoding)](https://cwe.mitre.org/data/definitions/177.html): The product does not properly handle when all or part of an input has been URL encoded.
- [CWE-838: Inappropriate Encoding for Output Context](https://cwe.mitre.org/data/definitions/838.html): The product uses or specifies an encoding when generating output to a downstream component, but the specified encoding is not the same as the encoding that is expected by the downstream component.

## Prerequisites

- No new lines can be present in the injected CSS stringProper HTML or URL escaping of the " and ' characters is not presentThe attacker has control of two injection points: pre-string and post-string

## Skills required

- [High] Ability to craft a CSS injection

## Mitigations

- Design: Prior to performing CSS parsing, require the CSS to start with well-formed CSS when it is a cross-domain load and the MIME type is broken. This is a browser level fix.
- Implementation: Perform proper HTML encoding and URL escaping

## Related pages

- [CAPEC-64: Using Slashes and URL Encoding Combined to Bypass Validation Logic](/mitre/capec/CAPEC-64.md), also related to CWE-177 and CWE-707
- [CAPEC-72: URL Encoding](/mitre/capec/CAPEC-72.md), also related to CWE-177
- [CAPEC-120: Double Encoding](/mitre/capec/CAPEC-120.md), also related to CWE-177
- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-707
- [CAPEC-7: Blind SQL Injection](/mitre/capec/CAPEC-7.md), also related to CWE-707
- [CAPEC-43: Exploiting Multiple Input Interpretation Layers](/mitre/capec/CAPEC-43.md), also related to CWE-707
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
