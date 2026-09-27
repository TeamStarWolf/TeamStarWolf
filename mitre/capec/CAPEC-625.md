# CAPEC-625 — Mobile Device Fault Injection

<a id="capec-625"></a>

**Abstraction:** Standard  
**Typical severity:**   
**Likelihood:** 

Fault injection attacks against mobile devices use disruptive signals or events (e.g. electromagnetic pulses, laser pulses, clock glitches, etc.) to cause faulty behavior. When performed in a controlled manner on devices performing cryptographic operations, this faulty behavior can be exploited to derive secret key information. Although this attack usually requires physical control of the mobile d

## Related CWE (8)

[CWE-1247](/CWE_REFERENCE.md) [CWE-1248](/CWE_REFERENCE.md) [CWE-1256](/CWE_REFERENCE.md) [CWE-1319](/CWE_REFERENCE.md) [CWE-1332](/CWE_REFERENCE.md) [CWE-1334](/CWE_REFERENCE.md) [CWE-1338](/CWE_REFERENCE.md) [CWE-1351](/CWE_REFERENCE.md)

**Skills required:** ::SKILL:Adversaries require non-trivial technical skills to create and implement fault injection attacks on mobile devices. Although this style of att

**Mitigations:** ::Strong physical security of all devices that contain secret key information. (even when devices are not in use)::Frequent changes to secret keys and certificates.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
