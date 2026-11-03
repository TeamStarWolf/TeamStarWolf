# CAPEC-229: Serialized Data Parameter Blowup

<a id="capec-229"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

This attack exploits certain serialized data parsers (e.g., XML, YAML, etc.) which manage data in an inefficient manner. The attacker crafts an serialized data file with multiple configuration parameters in the same dataset. In a vulnerable parser, this results in a denial of service condition where CPU resources are exhausted because of the parsing algorithm. The weakness being exploited is tied to parser implementation and not language specific.

## Related CWE (1)

- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html): The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- The server accepts input in the form of serialized data and is using a parser with a runtime longer than O(n) for the insertion of a new configuration parameter in the data container.(examples are .NET framework 1.0 and 1.1)

## Mitigations

- This attack may be mitigated completely by using a parser that is not using a vulnerable container.
- Mitigation may limit the number of configuration parameters per dataset.

## Related pages

- [CAPEC-125: Flooding](/mitre/capec/CAPEC-125.md), also related to CWE-770
- [CAPEC-130: Excessive Allocation](/mitre/capec/CAPEC-130.md), also related to CWE-770
- [CAPEC-147: XML Ping of the Death](/mitre/capec/CAPEC-147.md), also related to CWE-770
- [CAPEC-197: Exponential Data Expansion](/mitre/capec/CAPEC-197.md), also related to CWE-770
- [CAPEC-230: Serialized Data with Nested Payloads](/mitre/capec/CAPEC-230.md), also related to CWE-770
- [CAPEC-231: Oversized Serialized Data Payloads](/mitre/capec/CAPEC-231.md), also related to CWE-770
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
