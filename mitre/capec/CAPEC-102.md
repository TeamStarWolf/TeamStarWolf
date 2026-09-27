# CAPEC-102 — Session Sidejacking

<a id="capec-102"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

Session sidejacking takes advantage of an unencrypted communication channel between a victim and target system. The attacker sniffs traffic on a network looking for session tokens in unencrypted traffic. Once a session token is captured, the attacker performs malicious actions by using the stolen token with the targeted application to impersonate the victim. This attack is a specific method of ses

## Related CWE (5)

[CWE-294](/CWE_REFERENCE.md) [CWE-522](/CWE_REFERENCE.md) [CWE-523](/CWE_REFERENCE.md) [CWE-319](/CWE_REFERENCE.md) [CWE-614](/CWE_REFERENCE.md)

**Prerequisites:** ::An attacker and the victim are both using the same WiFi network.::The victim has an active session with a target system.::The victim is not using a secure channel to communicate with the target syst

**Skills required:** ::SKILL:Easy to use tools exist to automate this attack.:LEVEL:Low::

**Mitigations:** ::Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel.::Modify the session 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
