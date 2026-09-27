# CAPEC-5 — Blue Boxing

<a id="capec-5"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium

This type of attack against older telephone switches and trunks has been around for decades. A tone is sent by an adversary to impersonate a supervisor signal which has the effect of rerouting or usurping command of the line. While the US infrastructure proper may not contain widespread vulnerabilities to this type of attack, many companies are connected globally through call centers and business

## Related CWE (1)

[CWE-285](/CWE_REFERENCE.md)

**Prerequisites:** ::System must use weak authentication mechanisms for administrative functions.::

**Skills required:** ::SKILL:Given a vulnerable phone system, the attackers' technical vector relies on attacks that are well documented in cracker 'zines and have been ar

**Mitigations:** ::Implementation: Upgrade phone lines. Note this may be prohibitively expensive::Use strong access control such as two factor access control for administrative access to the switch::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
