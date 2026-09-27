# CAPEC-612 — WiFi MAC Address Tracking

<a id="capec-612"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** 

In this attack scenario, the attacker passively listens for WiFi messages and logs the associated Media Access Control (MAC) addresses. These addresses are intended to be unique to each wireless device (although they can be configured and changed by software). Once the attacker is able to associate a MAC address with a particular user or set of users (for example, when attending a public event), t

## Related CWE (2)

[CWE-201](/CWE_REFERENCE.md) [CWE-300](/CWE_REFERENCE.md)

**Prerequisites:** ::None::

**Skills required:** ::SKILL:Open source and commercial software tools are available and several commercial advertising companies routinely set up tools to collect and mon

**Mitigations:** ::Automatic randomization of WiFi MAC addresses::Frequent changing of handset and retransmission device::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
