# CAPEC-167: White Box Reverse Engineering

<a id="capec-167"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

An attacker discovers the structure, function, and composition of a type of computer software through white box analysis techniques. White box techniques involve methods which can be applied to a piece of software when an executable or some other compiled object can be directly subjected to analysis, revealing at least a portion of its machine instructions that can be observed upon execution.

## Related CWE (1)

- [CWE-1323: Improper Management of Sensitive Trace Data](https://cwe.mitre.org/data/definitions/1323.html): Trace data collected from several sources on the System-on-Chip (SoC) is stored in unprotected locations or transported to untrusted agents.

## Prerequisites

- Direct access to the object or software.

## Related pages

- [CAPEC-150: Collect Data from Common Resource Locations](/mitre/capec/CAPEC-150.md), also related to CWE-1323
- [CAPEC-545: Pull Data from System Resources](/mitre/capec/CAPEC-545.md), also related to CWE-1323
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
