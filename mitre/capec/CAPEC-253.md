# CAPEC-253: Remote Code Inclusion

<a id="capec-253"></a>

Abstraction: Standard  
Status: Draft  

The attacker forces an application to load arbitrary code files from a remote location. The attacker could use this to try to load old versions of library files that have known vulnerabilities, to load malicious files that the attacker placed on the remote machine, or to otherwise change the functionality of the targeted application in unexpected ways.

## Related CWE (1)

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html): The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- Target application server must allow remote files to be included.The malicious file must be placed on the remote machine previously.

## Mitigations

- Minimize attacks by input validation and sanitization of any user data that will be used by the target application to locate a remote file to be included.

## Related pages

- [CAPEC-175: Code Inclusion](/mitre/capec/CAPEC-175.md), also related to CWE-829
- [CAPEC-201: Serialized Data External Linking](/mitre/capec/CAPEC-201.md), also related to CWE-829
- [CAPEC-228: DTD Injection](/mitre/capec/CAPEC-228.md), also related to CWE-829
- [CAPEC-251: Local Code Inclusion](/mitre/capec/CAPEC-251.md), also related to CWE-829
- [CAPEC-252: PHP Local File Inclusion](/mitre/capec/CAPEC-252.md), also related to CWE-829
- [CAPEC-263: Force Use of Corrupted Files](/mitre/capec/CAPEC-263.md), also related to CWE-829
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
