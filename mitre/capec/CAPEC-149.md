# CAPEC-149: Explore for Predictable Temporary File Names

<a id="capec-149"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

An attacker explores a target to identify the names and locations of predictable temporary files for the purpose of launching further attacks against the target. This involves analyzing naming conventions and storage locations of the temporary files created by a target application. If an attacker can predict the names of temporary files they can use this information to mount other attacks, such as information gathering and symlink attacks.

## Related CWE (1)

- [CWE-377: DEPRECATED: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html): This entry has been deprecated.

## Prerequisites

- The targeted application must create names for temporary files using a predictable procedure, e.g. using sequentially increasing numbers.
- The attacker must be able to see the names of the files the target is creating.

## Related pages

- [CAPEC-155: Screen Temporary Files for Sensitive Information](/mitre/capec/CAPEC-155.md), also related to CWE-377
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
