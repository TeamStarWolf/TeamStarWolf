# CAPEC-62 — Cross Site Request Forgery

<a id="capec-62"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

An attacker crafts malicious web links and distributes them (via web pages, email, etc.), typically in a targeted manner, hoping to induce users to click on the link and execute the malicious action against some third-party application. If successful, the action embedded in the malicious link will be processed and accepted by the targeted application with the users' privilege level. This type of a

## Related CWE (5)

[CWE-352](/CWE_REFERENCE.md) [CWE-306](/CWE_REFERENCE.md) [CWE-664](/CWE_REFERENCE.md) [CWE-732](/CWE_REFERENCE.md) [CWE-1275](/CWE_REFERENCE.md)

**Skills required:** ::SKILL:The attacker needs to figure out the exact invocation of the targeted malicious action and then craft a link that performs the said action. Ha

**Mitigations:** ::Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arr


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
