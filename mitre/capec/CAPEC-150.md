# CAPEC-150: Collect Data from Common Resource Locations

<a id="capec-150"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

An adversary exploits well-known locations for resources for the purposes of undermining the security of the target. In many, if not most systems, files and resources are organized in a default tree structure. This can be useful for adversaries because they often know where to look for resources or files that are necessary for attacks. Even when the precise location of a targeted resource may not be known, naming conventions may indicate a small area of the target machine's file tree where the resources are typically located. For example, configuration files are normally stored in the /etc director on Unix systems. Adversaries can take advantage of this to commit other types of attacks.

## Mapped ATT&CK techniques (6)

- [T1003: OS Credential Dumping](/mitre/techniques/T1003.md): Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password.
- [T1119: Automated Collection](/mitre/techniques/T1119.md): Once established within a system or network, an adversary may use automated techniques for collecting internal data.
- [T1213: Data from Information Repositories](/mitre/techniques/T1213.md): Adversaries may leverage information repositories to mine valuable information.
- [T1530: Data from Cloud Storage](/mitre/techniques/T1530.md): Adversaries may access data from cloud storage.
- [T1555: Credentials from Password Stores](/mitre/techniques/T1555.md): Adversaries may search for common password storage locations to obtain user credentials.
- [T1602: Data from Configuration Repository](/mitre/techniques/T1602.md): Adversaries may collect data related to managed devices from configuration repositories.

## Related CWE (7)

- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html): The product makes files or directories accessible to unauthorized actors, even though they should not be.
- [CWE-1239: Improper Zeroization of Hardware Register](https://cwe.mitre.org/data/definitions/1239.html): The hardware product does not properly clear sensitive information from built-in registers when the user of the hardware block changes.
- [CWE-1258: Exposure of Sensitive System Information Due to Uncleared Debug Information](https://cwe.mitre.org/data/definitions/1258.html): The hardware product enters debug mode but does not fully clear security-sensitive values, such as keys and intermediate values in cryptographic operations.
- [CWE-1266: Improper Scrubbing of Sensitive Data from Decommissioned Device](https://cwe.mitre.org/data/definitions/1266.html): The product does not properly provide a capability for the product administrator to remove sensitive data at the time the product is decommissioned.
- [CWE-1272: Sensitive Information Uncleared Before Debug/Power State Transition](https://cwe.mitre.org/data/definitions/1272.html): The product performs a power or debug state transition, but it does not clear sensitive information that should no longer be accessible due to changes to information access restrictions.
- [CWE-1323: Improper Management of Sensitive Trace Data](https://cwe.mitre.org/data/definitions/1323.html): Trace data collected from several sources on the System-on-Chip (SoC) is stored in unprotected locations or transported to untrusted agents.
- [CWE-1330: Remanent Data Readable after Memory Erase](https://cwe.mitre.org/data/definitions/1330.html): Confidential information stored in memory circuits is readable or recoverable after being cleared or erased, i.e., there is data remanence.

## Prerequisites

- The targeted applications must either expect files to be located at a specific location or, if the location of the files can be configured by the user, the user either failed to move the files from the default location or placed them in a conventional location for files of the given type.

## Related pages

- [CAPEC-545: Pull Data from System Resources](/mitre/capec/CAPEC-545.md), also related to CWE-1239, CWE-1258 and 4 more
- [CAPEC-37: Retrieve Embedded Sensitive Data](/mitre/capec/CAPEC-37.md), also related to CWE-1239, CWE-1258 and 3 more
- [CAPEC-204: Lifting Sensitive Data Embedded in Cache](/mitre/capec/CAPEC-204.md), also related to CWE-1239 and CWE-1258
- [CAPEC-546: Incomplete Data Deletion in a Multi-Tenant Environment](/mitre/capec/CAPEC-546.md), also related to CWE-1266 and CWE-1272
- [CAPEC-639: Probe System Files](/mitre/capec/CAPEC-639.md), also related to CWE-552
- [CAPEC-167: White Box Reverse Engineering](/mitre/capec/CAPEC-167.md), also related to CWE-1323
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
