# D3FEND: Remote Firmware Update Monitoring

<a id="remote-firmware-update-monitoring"></a>

D3FEND tactic: Detect  
Digital artifacts: OT Device Firmware Command, OT Network Traffic  

Monitoring of remote firmware update commands to identify unauthorized software installations.

## ATT&CK techniques countered (3)

- [T0800: Activate Firmware Update Mode](https://attack.mitre.org/techniques/T0800): detects
- [T0814: Denial of Service](https://attack.mitre.org/techniques/T0814): monitors
- [T1693.002: Module Firmware](https://attack.mitre.org/techniques/T1693/002): detects (D3FEND maps the revoked predecessor T0839)

## Related pages

- [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), which also counters 3 of these techniques
- [Message Authentication](/mitre/d3fend/message-authentication.md), which also counters 2 of these techniques
- [Message Encryption](/mitre/d3fend/message-encryption.md), which also counters 2 of these techniques
- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 1 of these techniques
- [Application-based Process Isolation](/mitre/d3fend/application-based-process-isolation.md), which also counters 1 of these techniques
- [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md), which also counters 1 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
