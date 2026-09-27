# CAPEC-621 — Analysis of Packet Timing and Sizes

<a id="capec-621"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** 

An attacker may intercept and log encrypted transmissions for the purpose of analyzing metadata such as packet timing and sizes. Although the actual data may be encrypted, this metadata may reveal valuable information to an attacker. Note that this attack is applicable to VOIP data as well as application data, especially for interactive apps that require precise timing and low-latency (e.g. thin-c

## Related CWE (1)

[CWE-201](/CWE_REFERENCE.md)

**Prerequisites:** ::Use of untrusted communication paths enables an attacker to intercept and log communications, including metadata such as packet timing and sizes.::

**Skills required:** ::SKILL:These attacks generally require sophisticated machine learning techniques and require traffic capture as a prerequisite.:LEVEL:High::

**Mitigations:** ::Distort packet sizes and timing at VPN layer by adding padding to normalize packet sizes and timing delays to reduce information leakage via timing.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
