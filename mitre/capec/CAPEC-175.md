# CAPEC-175: Code Inclusion

<a id="capec-175"></a>

Abstraction: Meta  
Typical severity: Very High  
Likelihood: Medium  
Status: Stable  

An adversary exploits a weakness on the target to force arbitrary code to be retrieved locally or from a remote location and executed. This differs from code injection in that code injection involves the direct inclusion of code while code inclusion involves the addition or replacement of a reference to a code file, which is subsequently loaded by the target and used as part of the code of some application.

## Related CWE (1)

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html): The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- The target application must include external code/libraries that are executed when the application runs and the adversary must be able to influence the specific files that get included.
- The victim must run the targeted application, possibly using the crafted parameters that the adversary uses to identify the code to include.

## Related pages

- [CAPEC-201: Serialized Data External Linking](/mitre/capec/CAPEC-201.md), also related to CWE-829
- [CAPEC-228: DTD Injection](/mitre/capec/CAPEC-228.md), also related to CWE-829
- [CAPEC-251: Local Code Inclusion](/mitre/capec/CAPEC-251.md), also related to CWE-829
- [CAPEC-252: PHP Local File Inclusion](/mitre/capec/CAPEC-252.md), also related to CWE-829
- [CAPEC-253: Remote Code Inclusion](/mitre/capec/CAPEC-253.md), also related to CWE-829
- [CAPEC-263: Force Use of Corrupted Files](/mitre/capec/CAPEC-263.md), also related to CWE-829
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
