# CAPEC-174 — Flash Parameter Injection

<a id="capec-174"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** High

An adversary takes advantage of improper data validation to inject malicious global parameters into a Flash file embedded within an HTML document. Flash files can leverage user-submitted data to configure the Flash document and access the embedding HTML document.

## Related CWE (1)

[CWE-88](/CWE_REFERENCE.md)

**Skills required:** ::SKILL:The adversary need inject values into the global parameters to the Flash file and understand the parent HTML document DOM structure. The adver

**Mitigations:** ::User input must be sanitized according to context before reflected back to the user. The JavaScript function 'encodeURI' is not always sufficient for sanitizing input intended for global Flash parameters. Extreme caution should be taken when saving


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
