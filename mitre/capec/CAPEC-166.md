# CAPEC-166 — Force the System to Reset Values

<a id="capec-166"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** 

An attacker forces the target into a previous state in order to leverage potential weaknesses in the target dependent upon a prior configuration or state-dependent factors. Even in cases where an attacker may not be able to directly control the configuration of the targeted application, they may be able to reset the configuration to a prior state since many applications implement reset functions.

## Related CWE (3)

[CWE-306](/CWE_REFERENCE.md) [CWE-1221](/CWE_REFERENCE.md) [CWE-1232](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted application must have a reset function that returns the configuration of the application to an earlier state.::The reset functionality must be inadequately protected against use.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
