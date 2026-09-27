# CAPEC-72 — URL Encoding

<a id="capec-72"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This attack targets the encoding of the URL. An adversary can take advantage of the multiple way of encoding an URL and abuse the interpretation of the URL.

## Related CWE (6)

[CWE-173](/CWE_REFERENCE.md) [CWE-177](/CWE_REFERENCE.md) [CWE-172](/CWE_REFERENCE.md) [CWE-73](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md)

**Prerequisites:** ::The application should accepts and decodes URL input.::The application performs insufficient filtering/canonicalization on the URLs.::

**Skills required:** ::SKILL:An adversary can try special characters in the URL and bypass the URL validation.:LEVEL:Low::SKILL:The adversary may write a script to defeat 

**Mitigations:** ::Refer to the RFCs to safely decode URL.::Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive.::There are tools to scan HTTP requests to the server for 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
