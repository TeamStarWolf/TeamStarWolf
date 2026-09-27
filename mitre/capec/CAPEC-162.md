# CAPEC-162 — Manipulating Hidden Fields

<a id="capec-162"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** 

An adversary exploits a weakness in the server's trust of client-side processing by modifying data on the client-side, such as price information, and then submitting this data to the server, which processes the modified data. For example, eShoplifting is a data manipulation attack against an on-line merchant during a purchasing transaction. The manipulation of price, discount or quantity fields in

## Related CWE (1)

[CWE-602](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted site must contain hidden fields to be modified.::The targeted site must not validate the hidden fields with backend processing.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
