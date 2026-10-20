# CAPEC-572: Artificially Inflate File Sizes

<a id="capec-572"></a>

Abstraction: Standard  
Typical severity: Medium  
Likelihood: High  
Status: Draft  

An adversary modifies file contents by adding data to files for several reasons. Many different attacks could “follow” this pattern resulting in numerous outcomes. Adding data to a file could also result in a Denial of Service condition for devices with limited storage capacity.

## Mapped ATT&CK techniques (1)

- [T1027.001: Binary Padding](/mitre/techniques/T1027-001.md): Adversaries may use binary padding to add junk data and change the on-disk representation of malware.

## Consequences

- Availability / Resource Consumption
- Integrity / Modify Data

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
