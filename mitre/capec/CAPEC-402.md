# CAPEC-402 — Bypassing ATA Password Security

<a id="capec-402"></a>

**Abstraction:** Detailed  
**Status:** Draft  

An adversary exploits a weakness in ATA security on a drive to gain access to the information the drive contains without supplying the proper credentials. ATA Security is often employed to protect hard disk information from unauthorized access. The mechanism requires the user to type in a password before the BIOS is allowed access to drive contents. Some implementations of ATA security will accept the ATA command to update the password without the user having authenticated with the BIOS. This occurs because the security mechanism assumes the user has first authenticated via the BIOS prior to sending commands to the drive. Various methods exist for exploiting this flaw, the most common being installing the ATA protected drive into a system lacking ATA security features (a.k.a. hot swapping). Once the drive is installed into the new system the BIOS can be used to reset the drive password.

## Related CWE (1)

- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) — The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.

## Prerequisites

- Access to the system containing the ATA Drive so that the drive can be physically removed from the system.

## Mitigations

- Avoid using ATA password security when possible.
- Use full disk encryption to protect the entire contents of the drive or sensitive partitions on the drive.
- Leverage third-party utilities that interface with self-encrypting drives (SEDs) to provide authentication, while relying on the SED itself for data encryption.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
