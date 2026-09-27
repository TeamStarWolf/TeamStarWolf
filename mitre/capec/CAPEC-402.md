# CAPEC-402 — Bypassing ATA Password Security

<a id="capec-402"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

An adversary exploits a weakness in ATA security on a drive to gain access to the information the drive contains without supplying the proper credentials. ATA Security is often employed to protect hard disk information from unauthorized access. The mechanism requires the user to type in a password before the BIOS is allowed access to drive contents. Some implementations of ATA security will accept

## Related CWE (1)

[CWE-285](/CWE_REFERENCE.md)

**Prerequisites:** ::Access to the system containing the ATA Drive so that the drive can be physically removed from the system.::

**Mitigations:** ::Avoid using ATA password security when possible.::Use full disk encryption to protect the entire contents of the drive or sensitive partitions on the drive.::Leverage third-party utilities that interface with self-encrypting drives (SEDs) to provid


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
