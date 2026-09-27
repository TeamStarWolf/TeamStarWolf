# CAPEC-244 — XSS Targeting URI Placeholders

<a id="capec-244"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

An attack of this type exploits the ability of most browsers to interpret data, javascript or other URI schemes as client-side executable content placeholders. This attack consists of passing a malicious URI in an anchor tag HREF attribute or any other similar attributes in other HTML tags. Such malicious URI contains, for example, a base64 encoded HTML content with an embedded cross-site scriptin

## Related CWE (1)

[CWE-83](/CWE_REFERENCE.md)

**Prerequisites:** ::Target client software must allow scripting such as JavaScript and allows executable content delivered using a data URI scheme.::

**Skills required:** ::SKILL:To inject the malicious payload in a web page:LEVEL:Medium::

**Mitigations:** ::Design: Use browser technologies that do not allow client side scripting.::Design: Utilize strict type, character, and encoding enforcement.::Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
