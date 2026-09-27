# CAPEC-90 — Reflection Attack in Authentication Protocol

<a id="capec-90"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An adversary can abuse an authentication protocol susceptible to reflection attack in order to defeat it. Doing so allows the adversary illegitimate access to the target system, without possessing the requisite credentials. Reflection attacks are of great concern to authentication protocols that rely on a challenge-handshake or similar mechanism. An adversary can impersonate a legitimate user and

## Related CWE (2)

[CWE-301](/CWE_REFERENCE.md) [CWE-303](/CWE_REFERENCE.md)

**Prerequisites:** ::The attacker must have direct access to the target server in order to successfully mount a reflection attack. An intermediate entity, such as a router or proxy, that handles these exchanges on behal

**Skills required:** ::SKILL:The attacker needs to have knowledge of observing the protocol exchange and managing the required connections in order to issue and respond to

**Mitigations:** ::The server must initiate the handshake by issuing the challenge. This ensures that the client has to respond before the exchange can move any further::The use of HMAC to hash the response from the server can also be used to thwart reflection. The s


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
