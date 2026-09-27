# CAPEC-216 — Communication Channel Manipulation

<a id="capec-216"></a>

**Abstraction:** Meta  
**Typical severity:**   
**Likelihood:** 

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

## Related CWE (1)

[CWE-306](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must leverage an open communications channel.::The channel on which the target communicates must be vulnerable to interception (e.g., adversary in the middle attack - CAPEC-94

**Mitigations:** ::Encrypt all sensitive communications using properly-configured cryptography.::Design the communication system such that it associates proper authentication/authorization with each channel/message.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
