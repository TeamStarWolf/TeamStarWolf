# CAPEC-135 — Format String Injection

<a id="capec-135"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An adversary includes formatting characters in a string input field on the target application. Most applications assume that users will provide static text and may respond unpredictably to the presence of formatting character. For example, in certain functions of the C programming languages such as printf, the formatting character %s will print the contents of a memory location expecting this loca

## Related CWE (3)

[CWE-134](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must accept a strings as user input, fail to sanitize string formatting characters in the user input, and process this string using functions that interpret string formatting 

**Skills required:** ::SKILL:In order to discover format string vulnerabilities it takes only low skill, however, converting this discovery into a working exploit requires

**Mitigations:** ::Limit the usage of formatting string functions.::Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
