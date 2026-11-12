# CAPEC-233: Privilege Escalation

<a id="capec-233"></a>

Abstraction: Meta  
Status: Draft  

An adversary exploits a weakness enabling them to elevate their privilege and perform an action that they are not supposed to be authorized to perform.

## Mapped ATT&CK techniques (1)

- [T1548: Abuse Elevation Control Mechanism](/mitre/techniques/T1548.md): Adversaries may circumvent mechanisms designed to control privilege elevation to gain higher-level permissions.

## Related CWE (3)

- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html): The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.
- [CWE-1264: Hardware Logic with Insecure De-Synchronization between Control and Data Channels](https://cwe.mitre.org/data/definitions/1264.html): The hardware logic for error handling and security checks can incorrectly forward data before the security check is complete.
- [CWE-1311: Improper Translation of Security Attributes by Fabric Bridge](https://cwe.mitre.org/data/definitions/1311.html): The fabric bridge incorrectly translates security attributes from either trusted to untrusted or from untrusted to trusted when converting from one fabric protocol to another.

## Related pages

- [CAPEC-663: Exploitation of Transient Instruction Execution](/mitre/capec/CAPEC-663.md), also related to CWE-1264
- [CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs](/mitre/capec/CAPEC-1.md), also related to CWE-1311
- [CAPEC-58: Restful Privilege Elevation](/mitre/capec/CAPEC-58.md), also related to CWE-269
- [CAPEC-122: Privilege Abuse](/mitre/capec/CAPEC-122.md), also related to CWE-269
- [CAPEC-180: Exploiting Incorrectly Configured Access Control Security Levels](/mitre/capec/CAPEC-180.md), also related to CWE-1311
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
