# CAPEC-83 — XPath Injection

<a id="capec-83"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

An attacker can craft special user-controllable input consisting of XPath expressions to inject the XML database and bypass authentication or glean information that they normally would not be able to. XPath Injection enables an attacker to talk directly to the XML database, thus bypassing the application completely. XPath Injection results from the failure of an application to properly sanitize in

## Related CWE (4)

[CWE-91](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-707](/CWE_REFERENCE.md)

**Prerequisites:** ::XPath queries used to retrieve information stored in XML documents::User-controllable input not properly sanitized before being used as part of XPath queries::

**Skills required:** ::SKILL:XPath Injection shares the same basic premises with SQL Injection. An attacker must have knowledge of XPath syntax and constructs in order to 

**Mitigations:** ::Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XPath expression. Characters such as a single-quote(') or operators such as 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
