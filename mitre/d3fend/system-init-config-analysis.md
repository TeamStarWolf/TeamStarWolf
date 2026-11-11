# D3FEND: System Init Config Analysis

<a id="system-init-config-analysis"></a>

D3FEND tactic: Detect  
Digital artifacts: System Init Configuration  

Analysis of any system process startup configuration.

## ATT&CK techniques countered (5)

- [T1037.004: RC Scripts](/mitre/techniques/T1037-004.md): analyzes. Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup.
- [T1037.005: Startup Items](/mitre/techniques/T1037-005.md): analyzes. Adversaries may use startup items automatically executed at boot initialization to establish persistence.
- [T1547.001: Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md): analyzes. Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.
- [T1574.011: Services Registry Permissions Weakness](/mitre/techniques/T1574-011.md): analyzes. Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
- [T1688: Safe Mode Boot](/mitre/techniques/T1688.md): analyzes (D3FEND maps the revoked predecessor T1562.009). Adversaries may abuse Windows safe mode to disable endpoint defenses.

## Related pages

- [Configuration Inventory](/mitre/d3fend/configuration-inventory.md), which also counters 5 of these techniques
- [Restore Configuration](/mitre/d3fend/restore-configuration.md), which also counters 5 of these techniques
- [Content Quarantine](/mitre/d3fend/content-quarantine.md), which also counters 4 of these techniques
- [Local File Permissions](/mitre/d3fend/local-file-permissions.md), which also counters 3 of these techniques
- [Content Filtering](/mitre/d3fend/content-filtering.md), which also counters 2 of these techniques
- [Content Modification](/mitre/d3fend/content-modification.md), which also counters 2 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
