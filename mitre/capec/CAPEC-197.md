# CAPEC-197 — Exponential Data Expansion

<a id="capec-197"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** High  
**Status:** Draft  

An adversary submits data to a target application which contains nested exponential data expansion to produce excessively large output. Many data format languages allow the definition of macro-like structures that can be used to simplify the creation of complex structures. However, this capability can be abused to create excessive demands on a processor's CPU and memory. A small number of nested e

## Related CWE (2)

- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [CWE-776 — Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

## Prerequisites

- This type of attack requires that the target must receive input but either fail to provide an upper limit for entity expansion or provide a limit that is so large that it does not preclude significa

## Skills required

- Ability to craft nested data expansion messages.:LEVEL:Low

## Mitigations

- Design: Use libraries and templates that minimize unfiltered input. Use methods that limit entity expansion and throw exceptions on attempted entity expansion.
- Implementation: For XML based data - disable altogether the use of inline DTD schemas w

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
