# CAPEC-72 — URL Encoding

<a id="capec-72"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets the encoding of the URL. An adversary can take advantage of the multiple way of encoding an URL and abuse the interpretation of the URL.

## Related CWE (6)

- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html)
- [CWE-177 — Improper Handling of URL Encoding (Hex Encoding)](https://cwe.mitre.org/data/definitions/177.html)
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html)
- [CWE-73 — External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Prerequisites

- The application should accepts and decodes URL input.
- The application performs insufficient filtering/canonicalization on the URLs.

## Skills required

- An adversary can try special characters in the URL and bypass the URL validation.:LEVEL:Low
- The adversary may write a script to defeat

## Mitigations

- Refer to the RFCs to safely decode URL.
- Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive.
- There are tools to scan HTTP requests to the server for

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
