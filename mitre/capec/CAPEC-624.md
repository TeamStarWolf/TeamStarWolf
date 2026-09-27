# CAPEC-624 — Hardware Fault Injection

<a id="capec-624"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Low

The adversary uses disruptive signals or events, or alters the physical environment a device operates in, to cause faulty behavior in electronic devices. This can include electromagnetic pulses, laser pulses, clock glitches, ambient temperature extremes, and more. When performed in a controlled manner on devices performing cryptographic operations, this faulty behavior can be exploited to derive s

## Related CWE (8)

[CWE-1247](/CWE_REFERENCE.md) [CWE-1248](/CWE_REFERENCE.md) [CWE-1256](/CWE_REFERENCE.md) [CWE-1319](/CWE_REFERENCE.md) [CWE-1332](/CWE_REFERENCE.md) [CWE-1334](/CWE_REFERENCE.md) [CWE-1338](/CWE_REFERENCE.md) [CWE-1351](/CWE_REFERENCE.md)

**Prerequisites:** ::Physical access to the system::The adversary must be cognizant of where fault injection vulnerabilities exist in the system in order to leverage them for exploitation.::

**Skills required:** ::SKILL:Adversaries require non-trivial technical skills to create and implement fault injection attacks. Although this style of attack has become eas

**Mitigations:** ::Implement robust physical security countermeasures and monitoring.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
