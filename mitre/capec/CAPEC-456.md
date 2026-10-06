# CAPEC-456: Infected Memory

<a id="capec-456"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Medium  
Status: Stable  

An adversary inserts malicious logic into memory enabling them to achieve a negative impact. This logic is often hidden from the user of the system and works behind the scenes to achieve negative impacts. This pattern of attack focuses on systems already fielded and used in operation as opposed to systems that are still under development and part of the supply chain.

## Related CWE (5)

- [CWE-1257: Improper Access Control Applied to Mirrored or Aliased Memory Regions](https://cwe.mitre.org/data/definitions/1257.html): Aliased or mirrored memory regions in hardware designs may have inconsistent read/write permissions enforced by the hardware.
- [CWE-1260: Improper Handling of Overlap Between Protected Memory Ranges](https://cwe.mitre.org/data/definitions/1260.html): The product allows address regions to overlap, which can result in the bypassing of intended memory protection.
- [CWE-1274: Improper Access Control for Volatile Memory Containing Boot Code](https://cwe.mitre.org/data/definitions/1274.html): The product conducts a secure-boot process that transfers bootloader code from Non-Volatile Memory (NVM) into Volatile Memory (VM), but it does not have sufficient access control or other protections for the Volatile Memory.
- [CWE-1312: Missing Protection for Mirrored Regions in On-Chip Fabric Firewall](https://cwe.mitre.org/data/definitions/1312.html): The firewall in an on-chip fabric protects the main addressed region, but it does not protect any mirrored memory or memory-mapped-IO (MMIO) regions.
- [CWE-1316: Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges](https://cwe.mitre.org/data/definitions/1316.html): The address map of the on-chip fabric has protected and unprotected regions overlapping, allowing an attacker to bypass access control to the overlapping portion of the protected region.

## Consequences

- Authorization / Execute Unauthorized Commands

## Mitigations

- Leverage anti-virus products to detect stop operations with known virus.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
