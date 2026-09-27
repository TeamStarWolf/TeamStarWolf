# CAPEC-590 — IP Address Blocking

<a id="capec-590"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

An adversary performing this type of attack drops packets destined for a target IP address. The aim is to prevent access to the service hosted at the target IP address.

## Related CWE (1)

[CWE-300](/CWE_REFERENCE.md)

**Prerequisites:** ::This attack requires the ability to conduct deep packet inspection with an In-Path device that can drop the targeted traffic and/or connection.::

**Mitigations:** ::Have a large pool of backup IPs built into the application and support proxy capability in the application.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
