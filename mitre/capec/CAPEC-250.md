# CAPEC-250 — XML Injection

<a id="capec-250"></a>

**Abstraction:** Standard  
**Typical severity:**   
**Likelihood:** High

An attacker utilizes crafted XML user-controllable input to probe, attack, and inject data into the XML database, using techniques similar to SQL injection. The user-controllable input can allow for unauthorized viewing of data, bypassing authentication or the front-end application for direct XML database access, and possibly altering database information.

## Related CWE (4)

[CWE-91](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-707](/CWE_REFERENCE.md)

**Prerequisites:** ::XML queries used to process user input and retrieve information stored in XML documents::User-controllable input not properly sanitized::

**Skills required:** ::SKILL:An attacker must have knowledge of XML syntax and constructs in order to successfully leverage XML Injection:LEVEL:Low::

**Mitigations:** ::Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query.::Use of custom error pages - Attackers can glean inform


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
