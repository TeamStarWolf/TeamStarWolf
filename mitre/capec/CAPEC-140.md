# CAPEC-140 — Bypassing of Intermediate Forms in Multiple-Form Sets

<a id="capec-140"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** 

Some web applications require users to submit information through an ordered sequence of web forms. This is often done if there is a very large amount of information being collected or if information on earlier forms is used to pre-populate fields or determine which additional information the application needs to collect. An attacker who knows the names of the various forms in the sequence may be

## Related CWE (1)

[CWE-372](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must collect information from the user in a series of forms where each form has its own URL that the attacker can anticipate and the application must fail to detect attempts to access int


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
