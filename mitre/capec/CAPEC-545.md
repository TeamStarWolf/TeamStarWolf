# CAPEC-545 — Pull Data from System Resources

<a id="capec-545"></a>

**Abstraction:** Standard  
**Status:** Draft  

An adversary who is authorized or has the ability to search known system resources, does so with the intention of gathering useful information. System resources include files, memory, and other aspects of the target system. In this pattern of attack, the adversary does not necessarily know what they are going to find when they start pulling data. This is different than CAPEC-150 where the adversar

## Mapped ATT&CK techniques (2)

- [T1005 — Data from Local System](/mitre/techniques/T1005.md)
- [T1555.001 — Keychain](/mitre/techniques/T1555-001.md)

## Related CWE (9)

- [CWE-1239 — Improper Zeroization of Hardware Register](https://cwe.mitre.org/data/definitions/1239.html)
- [CWE-1243 — Sensitive Non-Volatile Information Not Protected During Debug](https://cwe.mitre.org/data/definitions/1243.html)
- [CWE-1258 — Exposure of Sensitive System Information Due to Uncleared Debug Information](https://cwe.mitre.org/data/definitions/1258.html)
- [CWE-1266 — Improper Scrubbing of Sensitive Data from Decommissioned Device](https://cwe.mitre.org/data/definitions/1266.html)
- [CWE-1272 — Sensitive Information Uncleared Before Debug/Power State Transition](https://cwe.mitre.org/data/definitions/1272.html)
- [CWE-1278 — Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques](https://cwe.mitre.org/data/definitions/1278.html)
- [CWE-1323 — Improper Management of Sensitive Trace Data](https://cwe.mitre.org/data/definitions/1323.html)
- [CWE-1258 — Exposure of Sensitive System Information Due to Uncleared Debug Information](https://cwe.mitre.org/data/definitions/1258.html)
- [CWE-1330 — Remanent Data Readable after Memory Erase](https://cwe.mitre.org/data/definitions/1330.html)

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
