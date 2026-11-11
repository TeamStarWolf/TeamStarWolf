# D3FEND: Firmware Embedded Monitoring Code

<a id="firmware-embedded-monitoring-code"></a>

D3FEND tactic: Detect  
Digital artifacts: Firmware  

Monitoring code is injected into firmware for integrity monitoring of firmware and firmware data.

## ATT&CK techniques countered (6)

- [T0851: Rootkit](https://attack.mitre.org/techniques/T0851): analyzes
- [T1014: Rootkit](/mitre/techniques/T1014.md): analyzes. Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components.
- [T1542.001: System Firmware](/mitre/techniques/T1542-001.md): analyzes. Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer.
- [T1542.002: Component Firmware](/mitre/techniques/T1542-002.md): analyzes. Adversaries may modify component firmware to persist on systems.
- [T1542.004: ROMMONkit](/mitre/techniques/T1542-004.md): analyzes. Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized firmware with adversary code to provide persistent access and manipulate device behavior that is difficult to detect.
- [T1693.002: Module Firmware](https://attack.mitre.org/techniques/T1693/002): analyzes (D3FEND maps the revoked predecessor T0839)

## Related pages

- [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md), which also counters 6 of these techniques
- [Firmware Behavior Analysis](/mitre/d3fend/firmware-behavior-analysis.md), which also counters 6 of these techniques
- [Firmware Verification](/mitre/d3fend/firmware-verification.md), which also counters 6 of these techniques
- [Restore Software](/mitre/d3fend/restore-software.md), which also counters 6 of these techniques
- [Software Inventory](/mitre/d3fend/software-inventory.md), which also counters 6 of these techniques
- [Software Update](/mitre/d3fend/software-update.md), which also counters 6 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
