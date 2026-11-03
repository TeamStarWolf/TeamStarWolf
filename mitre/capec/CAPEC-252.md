# CAPEC-252: PHP Local File Inclusion

<a id="capec-252"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

The attacker loads and executes an arbitrary local PHP file on a target machine. The attacker could use this to try to load old versions of PHP files that have known vulnerabilities, to load PHP files that the attacker placed on the local machine during a prior attack, or to otherwise change the functionality of the targeted application in unexpected ways.

## Related CWE (1)

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html): The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- The targeted PHP application must have a bug that allows an attacker to control which code file is loaded at some juncture.

## Related pages

- [CAPEC-175: Code Inclusion](/mitre/capec/CAPEC-175.md), also related to CWE-829
- [CAPEC-201: Serialized Data External Linking](/mitre/capec/CAPEC-201.md), also related to CWE-829
- [CAPEC-228: DTD Injection](/mitre/capec/CAPEC-228.md), also related to CWE-829
- [CAPEC-251: Local Code Inclusion](/mitre/capec/CAPEC-251.md), also related to CWE-829
- [CAPEC-253: Remote Code Inclusion](/mitre/capec/CAPEC-253.md), also related to CWE-829
- [CAPEC-263: Force Use of Corrupted Files](/mitre/capec/CAPEC-263.md), also related to CWE-829
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
