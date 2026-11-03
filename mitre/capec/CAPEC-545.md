# CAPEC-545: Pull Data from System Resources

<a id="capec-545"></a>

Abstraction: Standard  
Status: Draft  

An adversary who is authorized or has the ability to search known system resources, does so with the intention of gathering useful information. System resources include files, memory, and other aspects of the target system. In this pattern of attack, the adversary does not necessarily know what they are going to find when they start pulling data. This is different than CAPEC-150 where the adversary knows what they are looking for due to the common location.

## Mapped ATT&CK techniques (2)

- [T1005: Data from Local System](/mitre/techniques/T1005.md): Adversaries may search local system sources, such as file systems, configuration files, local databases, virtual machine files, or process memory, to find files of interest and sensitive data prior to Exfiltration.
- [T1555.001: Keychain](/mitre/techniques/T1555-001.md): Adversaries may acquire credentials from Keychain.

## Related CWE (9)

- [CWE-1239: Improper Zeroization of Hardware Register](https://cwe.mitre.org/data/definitions/1239.html): The hardware product does not properly clear sensitive information from built-in registers when the user of the hardware block changes.
- [CWE-1243: Sensitive Non-Volatile Information Not Protected During Debug](https://cwe.mitre.org/data/definitions/1243.html): Access to security-sensitive information stored in fuses is not limited during debug.
- [CWE-1258: Exposure of Sensitive System Information Due to Uncleared Debug Information](https://cwe.mitre.org/data/definitions/1258.html): The hardware product enters debug mode but does not fully clear security-sensitive values, such as keys and intermediate values in cryptographic operations.
- [CWE-1266: Improper Scrubbing of Sensitive Data from Decommissioned Device](https://cwe.mitre.org/data/definitions/1266.html): The product does not properly provide a capability for the product administrator to remove sensitive data at the time the product is decommissioned.
- [CWE-1272: Sensitive Information Uncleared Before Debug/Power State Transition](https://cwe.mitre.org/data/definitions/1272.html): The product performs a power or debug state transition, but it does not clear sensitive information that should no longer be accessible due to changes to information access restrictions.
- [CWE-1278: Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques](https://cwe.mitre.org/data/definitions/1278.html): Information stored in hardware may be recovered by an attacker with the capability to capture and analyze images of the integrated circuit using techniques such as scanning electron microscopy.
- [CWE-1323: Improper Management of Sensitive Trace Data](https://cwe.mitre.org/data/definitions/1323.html): Trace data collected from several sources on the System-on-Chip (SoC) is stored in unprotected locations or transported to untrusted agents.
- [CWE-1258: Exposure of Sensitive System Information Due to Uncleared Debug Information](https://cwe.mitre.org/data/definitions/1258.html): The hardware product enters debug mode but does not fully clear security-sensitive values, such as keys and intermediate values in cryptographic operations.
- [CWE-1330: Remanent Data Readable after Memory Erase](https://cwe.mitre.org/data/definitions/1330.html): Confidential information stored in memory circuits is readable or recoverable after being cleared or erased, i.e., there is data remanence.

## Related pages

- [CAPEC-150: Collect Data from Common Resource Locations](/mitre/capec/CAPEC-150.md), named in the description above
- [CAPEC-37: Retrieve Embedded Sensitive Data](/mitre/capec/CAPEC-37.md), also related to CWE-1239, CWE-1258 and 5 more
- [CAPEC-204: Lifting Sensitive Data Embedded in Cache](/mitre/capec/CAPEC-204.md), also related to CWE-1239, CWE-1258 and 1 more
- [CAPEC-546: Incomplete Data Deletion in a Multi-Tenant Environment](/mitre/capec/CAPEC-546.md), also related to CWE-1266 and CWE-1272
- [CAPEC-116: Excavation](/mitre/capec/CAPEC-116.md), also related to CWE-1243
- [CAPEC-167: White Box Reverse Engineering](/mitre/capec/CAPEC-167.md), also related to CWE-1323
- [CAPEC-188: Reverse Engineering](/mitre/capec/CAPEC-188.md), also related to CWE-1278
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
