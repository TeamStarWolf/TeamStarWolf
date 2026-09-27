# CAPEC-632 — Homograph Attack via Homoglyphs

<a id="capec-632"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Low

An adversary registers a domain name containing a homoglyph, leading the registered domain to appear the same as a trusted domain. A homograph attack leverages the fact that different characters among various character sets look the same to the user. Homograph attacks must generally be combined with other attacks, such as phishing attacks, in order to direct Internet traffic to the adversary-contr

## Related CWE (1)

[CWE-1007](/CWE_REFERENCE.md)

**Prerequisites:** ::An adversary requires knowledge of popular or high traffic domains, that could be used to deceive potential targets.::

**Skills required:** ::SKILL:Adversaries must be able to register DNS hostnames/URL’s.:LEVEL:Low::

**Mitigations:** ::Authenticate all servers and perform redundant checks when using DNS hostnames.::Utilize browsers that can warn users if URLs contain characters from different character sets.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
