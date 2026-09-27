# CAPEC-295 — Timestamp Request

<a id="capec-295"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** 

This pattern of attack leverages standard requests to learn the exact time associated with a target system. An adversary may be able to use the timestamp returned from the target to attack time-based security algorithms, such as random number generators, or time-based authentication mechanisms.

## Mapped ATT&CK techniques (1)

- [T1124](/mitre/techniques/T1124.md)

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::The ability to send a timestamp request to a remote target and receive a response.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
