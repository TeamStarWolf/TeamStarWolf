# CAPEC-491 — Quadratic Data Expansion

<a id="capec-491"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

An adversary exploits macro-like substitution to cause a denial of service situation due to excessive memory being allocated to fully expand the data. The result of this denial of service could cause the application to freeze or crash. This involves defining a very large entity and using it multiple times in a single entity substitution. CAPEC-197 is a similar attack pattern, but it is easier to d

## Related CWE (1)

[CWE-770](/CWE_REFERENCE.md)

**Prerequisites:** ::This type of attack requires a server that accepts serialization data which supports substitution and parses the data.::

**Mitigations:** ::Design: Use libraries and templates that minimize unfiltered input. Use methods that limit entity expansion and throw exceptions on attempted entity expansion.::Implementation: For XML based data - disable altogether the use of inline DTD schemas w


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
