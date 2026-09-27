# CAPEC-247 — XSS Using Invalid Characters

<a id="capec-247"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An adversary inserts invalid characters in identifiers to bypass application filtering of input. Filters may not scan beyond invalid characters but during later stages of processing content that follows these invalid characters may still be processed. This allows the adversary to sneak prohibited commands past filters and perform normally prohibited operations. Invalid characters may include null,

## Related CWE (1)

[CWE-86](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must fail to remove invalid characters from input and fail to adequately scan beyond these characters.::

**Mitigations:** ::Design: Use libraries and templates that minimize unfiltered input.::Implementation: Normalize, filter and use an allowlist for any input that will be included in any subsequent web pages or back end operations.::Implementation: The victim should c


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
