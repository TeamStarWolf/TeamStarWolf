# CAPEC-111 — JSON Hijacking (aka JavaScript Hijacking)

<a id="capec-111"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An attacker targets a system that uses JavaScript Object Notation (JSON) as a transport mechanism between the client and the server (common in Web 2.0 systems using AJAX) to steal possibly confidential information transmitted from the server back to the client inside the JSON object by taking advantage of the loophole in the browser's Same Origin Policy that does not prohibit JavaScript from one w

## Related CWE (3)

[CWE-345](/CWE_REFERENCE.md) [CWE-346](/CWE_REFERENCE.md) [CWE-352](/CWE_REFERENCE.md)

**Prerequisites:** ::JSON is used as a transport mechanism between the client and the server::The target server cannot differentiate real requests from forged requests::The JSON object returned from the server can be ac

**Skills required:** ::SKILL:Once this attack pattern is developed and understood, creating an exploit is not very complex.The attacker needs to have knowledge of the URLs

**Mitigations:** ::Ensure that server side code can differentiate between legitimate requests and forged requests. The solution is similar to protection against Cross Site Request Forger (CSRF), which is to use a hard to guess random nonce (that is unique to the vict


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
