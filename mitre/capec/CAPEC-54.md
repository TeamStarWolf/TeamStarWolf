# CAPEC-54 — Query System for Information

<a id="capec-54"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Likelihood:** High  
**Status:** Draft  

An adversary, aware of an application's location (and possibly authorized to use the application), probes an application's structure and evaluates its robustness by submitting requests and examining responses. Often, this is accomplished by sending variants of expected queries in the hope that these modified queries might return information beyond what the expected set of queries would provide.

## Related CWE (1)

- [CWE-209 — Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

## Prerequisites

- This class of attacks does not strictly require authorized access to the application. As Attackers use this attack process to classify, map, and identify vulnerable aspects of an application, it sim

## Skills required

- Although fuzzing parameters is not difficult, and often possible with automated fuzzers, interpreting the error conditions and modifying the p

## Mitigations

- Application designers can construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are cataloged and replaced with a unique (often integer-based) value 'codin

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
