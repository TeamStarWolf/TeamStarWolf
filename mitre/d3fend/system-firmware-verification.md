# D3FEND: System Firmware Verification

<a id="system-firmware-verification"></a>

D3FEND tactic: Detect  
Digital artifacts: System Firmware  

Cryptographically verifying installed system firmware integrity.

## ATT&CK techniques countered (2)

- [T1542.001: System Firmware](/mitre/techniques/T1542-001.md): verifies. Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer.
- [T1542.004: ROMMONkit](/mitre/techniques/T1542-004.md): verifies. Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized firmware with adversary code to provide persistent access and manipulate device behavior that is difficult to detect.

## Related pages

- [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md), which also counters 2 of these techniques
- [Firmware Behavior Analysis](/mitre/d3fend/firmware-behavior-analysis.md), which also counters 2 of these techniques
- [Firmware Embedded Monitoring Code](/mitre/d3fend/firmware-embedded-monitoring-code.md), which also counters 2 of these techniques
- [Firmware Verification](/mitre/d3fend/firmware-verification.md), which also counters 2 of these techniques
- [Restore Software](/mitre/d3fend/restore-software.md), which also counters 2 of these techniques
- [Software Inventory](/mitre/d3fend/software-inventory.md), which also counters 2 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
