# CAPEC-402: Bypassing ATA Password Security

<a id="capec-402"></a>

Abstraction: Detailed  
Status: Draft  

An adversary exploits a weakness in ATA security on a drive to gain access to the information the drive contains without supplying the proper credentials. ATA Security is often employed to protect hard disk information from unauthorized access. The mechanism requires the user to type in a password before the BIOS is allowed access to drive contents. Some implementations of ATA security will accept the ATA command to update the password without the user having authenticated with the BIOS. This occurs because the security mechanism assumes the user has first authenticated via the BIOS prior to sending commands to the drive. Various methods exist for exploiting this flaw, the most common being installing the ATA protected drive into a system lacking ATA security features (a.k.a. hot swapping). Once the drive is installed into the new system the BIOS can be used to reset the drive password.

## Related CWE (1)

- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html): The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.

## Prerequisites

- Access to the system containing the ATA Drive so that the drive can be physically removed from the system.

## Mitigations

- Avoid using ATA password security when possible.
- Use full disk encryption to protect the entire contents of the drive or sensitive partitions on the drive.
- Leverage third-party utilities that interface with self-encrypting drives (SEDs) to provide authentication, while relying on the SED itself for data encryption.

## Related pages

- [CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs](/mitre/capec/CAPEC-1.md), also related to CWE-285
- [CAPEC-5: Blue Boxing](/mitre/capec/CAPEC-5.md), also related to CWE-285
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-285
- [CAPEC-17: Using Malicious Files](/mitre/capec/CAPEC-17.md), also related to CWE-285
- [CAPEC-39: Manipulating Opaque Client-based Data Tokens](/mitre/capec/CAPEC-39.md), also related to CWE-285
- [CAPEC-45: Buffer Overflow via Symbolic Links](/mitre/capec/CAPEC-45.md), also related to CWE-285
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
