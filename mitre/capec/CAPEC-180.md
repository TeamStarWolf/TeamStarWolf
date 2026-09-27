# CAPEC-180 — Exploiting Incorrectly Configured Access Control Security Levels

<a id="capec-180"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** High

An attacker exploits a weakness in the configuration of access controls and is able to bypass the intended protection that these measures guard against and thereby obtain unauthorized access to the system or network. Sensitive functionality should always be protected with access controls. However configuring all but the most trivial access control systems can be very complicated and there are many

## Mapped ATT&CK techniques (1)

- [T1574.010](/mitre/techniques/T1574-010.md)

## Related CWE (13)

[CWE-732](/CWE_REFERENCE.md) [CWE-1190](/CWE_REFERENCE.md) [CWE-1191](/CWE_REFERENCE.md) [CWE-1193](/CWE_REFERENCE.md) [CWE-1220](/CWE_REFERENCE.md) [CWE-1268](/CWE_REFERENCE.md) [CWE-1280](/CWE_REFERENCE.md) [CWE-1297](/CWE_REFERENCE.md) [CWE-1311](/CWE_REFERENCE.md) [CWE-1315](/CWE_REFERENCE.md) [CWE-1318](/CWE_REFERENCE.md) [CWE-1320](/CWE_REFERENCE.md) [CWE-1321](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must apply access controls, but incorrectly configure them. However, not all incorrect configurations can be exploited by an attacker. If the incorrect configuration applies too little se

**Skills required:** ::SKILL:In order to discover unrestricted resources, the attacker does not need special tools or skills. They only have to observe the resources or ac

**Mitigations:** ::Design: Configure the access control correctly.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
