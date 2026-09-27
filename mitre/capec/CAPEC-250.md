# CAPEC-250 — XML Injection

<a id="capec-250"></a>

**Abstraction:** Standard  
**Likelihood:** High  
**Status:** Draft  

An attacker utilizes crafted XML user-controllable input to probe, attack, and inject data into the XML database, using techniques similar to SQL injection. The user-controllable input can allow for unauthorized viewing of data, bypassing authentication or the front-end application for direct XML database access, and possibly altering database information.

## Related CWE (4)

- [CWE-91 — XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-707 — Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html)

## Prerequisites

- XML queries used to process user input and retrieve information stored in XML documents
- User-controllable input not properly sanitized

## Skills required

- An attacker must have knowledge of XML syntax and constructs in order to successfully leverage XML Injection:LEVEL:Low

## Mitigations

- Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query.
- Use of custom error pages - Attackers can glean inform

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
