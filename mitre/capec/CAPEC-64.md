# CAPEC-64 — Using Slashes and URL Encoding Combined to Bypass Validation Logic

<a id="capec-64"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets the encoding of the URL combined with the encoding of the slash characters. An attacker can take advantage of the multiple ways of encoding a URL and abuse the interpretation of the URL. A URL may contain special character that need special syntax handling in order to be interpreted. Special characters are represented using a percentage character followed by two digits represen

## Related CWE (9)

- [CWE-177 — Improper Handling of URL Encoding (Hex Encoding)](https://cwe.mitre.org/data/definitions/177.html)
- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html)
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html)
- [CWE-73 — External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)
- [CWE-707 — Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html)

## Prerequisites

- The application accepts and decodes URL string request.
- The application performs insufficient filtering/canonicalization on the URLs.

## Skills required

- An attacker can try special characters in the URL and bypass the URL validation.:LEVEL:Low
- The attacker may write a script to defeat th

## Mitigations

- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system. Test

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
