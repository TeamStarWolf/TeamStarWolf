# CAPEC-564 — Run Software at Logon

<a id="capec-564"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

Operating system allows logon scripts to be run whenever a specific user or users logon to a system. If adversaries can access these scripts, they may insert additional code into the logon script. This code can allow them to maintain persistence or move laterally within an enclave because it is executed every time the affected user or users logon to a computer. Modifying logon scripts can effectiv

## Mapped ATT&CK techniques (4)

- [T1037](/mitre/techniques/T1037.md)
- [T1543.001](/mitre/techniques/T1543-001.md)
- [T1543.004](/mitre/techniques/T1543-004.md)
- [T1547](/mitre/techniques/T1547.md)

## Related CWE (1)

[CWE-284](/CWE_REFERENCE.md)

**Mitigations:** ::Restrict write access to logon scripts to necessary administrators.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
