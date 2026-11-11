# CAPEC-571: Block Logging to Central Repository

<a id="capec-571"></a>

Abstraction: Standard  
Typical severity: Low  
Status: Draft  

An adversary prevents host-generated logs being delivered to a central location in an attempt to hide indicators of compromise.

## Mapped ATT&CK techniques (4)

- [T1562.002: Disable Windows Event Logging](/mitre/techniques/T1562-002.md): Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits.
- [T1562.002: Disable Windows Event Logging](/mitre/techniques/T1562-002.md): Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits.
- [T1562.006: Indicator Blocking](/mitre/techniques/T1562-006.md): An adversary may attempt to block indicators or events typically captured by sensors from being gathered and analyzed.
- [T1562.008: Disable or Modify Cloud Logs](/mitre/techniques/T1562-008.md): An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection.

## Related pages

- [T1685: Disable or Modify Tools](/mitre/techniques/T1685.md), whose ATT&CK profile lists this pattern
- [T1685.001: Disable or Modify Windows Event Log](/mitre/techniques/T1685-001.md), whose ATT&CK profile lists this pattern
- [T1685.002: Disable or Modify Cloud Log](/mitre/techniques/T1685-002.md), whose ATT&CK profile lists this pattern
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
