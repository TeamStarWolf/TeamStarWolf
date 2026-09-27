# CAPEC-467 — Cross Site Identification

<a id="capec-467"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** 

An attacker harvests identifying information about a victim via an active session that the victim's browser has with a social networking site. A victim may have the social networking site open in one tab or perhaps is simply using the remember me feature to keep their session with the social networking site active. An attacker induces a payload to execute in the victim's browser that transparently

## Related CWE (2)

[CWE-352](/CWE_REFERENCE.md) [CWE-359](/CWE_REFERENCE.md)

**Prerequisites:** ::The victim has an active session with the social networking site.::

**Skills required:** ::SKILL:An attacker should be able to create a payload and deliver it to the victim's browser.:LEVEL:High::SKILL:An attacker needs to know how to inte

**Mitigations:** ::Usage: Users should always explicitly log out from the social networking sites when done using them.::Usage: Users should not open other tabs in the browser when using a social networking site.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
