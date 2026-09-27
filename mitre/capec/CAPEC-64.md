# CAPEC-64 — Using Slashes and URL Encoding Combined to Bypass Validation Logic

<a id="capec-64"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This attack targets the encoding of the URL combined with the encoding of the slash characters. An attacker can take advantage of the multiple ways of encoding a URL and abuse the interpretation of the URL. A URL may contain special character that need special syntax handling in order to be interpreted. Special characters are represented using a percentage character followed by two digits represen

## Related CWE (9)

[CWE-177](/CWE_REFERENCE.md) [CWE-173](/CWE_REFERENCE.md) [CWE-172](/CWE_REFERENCE.md) [CWE-73](/CWE_REFERENCE.md) [CWE-22](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md) [CWE-707](/CWE_REFERENCE.md)

**Prerequisites:** ::The application accepts and decodes URL string request.::The application performs insufficient filtering/canonicalization on the URLs.::

**Skills required:** ::SKILL:An attacker can try special characters in the URL and bypass the URL validation.:LEVEL:Low::SKILL:The attacker may write a script to defeat th

**Mitigations:** ::Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system. Test 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
