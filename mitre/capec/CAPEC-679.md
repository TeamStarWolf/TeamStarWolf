# CAPEC-679: Exploitation of Improperly Configured or Implemented Memory Protections

<a id="capec-679"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: Medium  
Status: Draft  

An adversary takes advantage of missing or incorrectly configured access control within memory to read/write data or inject malicious code into said memory.

## Related CWE (9)

- [CWE-1222: Insufficient Granularity of Address Regions Protected by Register Locks](https://cwe.mitre.org/data/definitions/1222.html): The product defines a large address region protected from modification by the same register lock control bit.
- [CWE-1252: CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations](https://cwe.mitre.org/data/definitions/1252.html): The CPU is not configured to provide hardware support for exclusivity of write and execute operations on memory.
- [CWE-1257: Improper Access Control Applied to Mirrored or Aliased Memory Regions](https://cwe.mitre.org/data/definitions/1257.html): Aliased or mirrored memory regions in hardware designs may have inconsistent read/write permissions enforced by the hardware.
- [CWE-1260: Improper Handling of Overlap Between Protected Memory Ranges](https://cwe.mitre.org/data/definitions/1260.html): The product allows address regions to overlap, which can result in the bypassing of intended memory protection.
- [CWE-1274: Improper Access Control for Volatile Memory Containing Boot Code](https://cwe.mitre.org/data/definitions/1274.html): The product conducts a secure-boot process that transfers bootloader code from Non-Volatile Memory (NVM) into Volatile Memory (VM), but it does not have sufficient access control or other protections for the Volatile Memory.
- [CWE-1282: Assumed-Immutable Data is Stored in Writable Memory](https://cwe.mitre.org/data/definitions/1282.html): Immutable data, such as a first-stage bootloader, device identifiers, and write-once configuration settings are stored in writable memory that can be re-programmed or updated in the field.
- [CWE-1312: Missing Protection for Mirrored Regions in On-Chip Fabric Firewall](https://cwe.mitre.org/data/definitions/1312.html): The firewall in an on-chip fabric protects the main addressed region, but it does not protect any mirrored memory or memory-mapped-IO (MMIO) regions.
- [CWE-1316: Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges](https://cwe.mitre.org/data/definitions/1316.html): The address map of the on-chip fabric has protected and unprotected regions overlapping, allowing an attacker to bypass access control to the overlapping portion of the protected region.
- [CWE-1326: Missing Immutable Root of Trust in Hardware](https://cwe.mitre.org/data/definitions/1326.html): A missing immutable root of trust in the hardware results in the ability to bypass secure boot or execute untrusted or adversarial boot code.

## Prerequisites

- Access to the hardware being leveraged.

## Skills required

- [Medium] Ability to craft malicious code to inject into the memory region.
- [High] Intricate knowledge of memory structures.

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Ensure that protected and unprotected memory ranges are isolated and do not overlap.
- If memory regions must overlap, leverage memory priority schemes if memory regions can overlap.
- Ensure that original and mirrored memory regions apply the same protections.
- Ensure immutable code or data is programmed into ROM or write-once memory.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
