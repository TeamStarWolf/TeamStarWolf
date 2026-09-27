# CAPEC-90 — Reflection Attack in Authentication Protocol

<a id="capec-90"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An adversary can abuse an authentication protocol susceptible to reflection attack in order to defeat it. Doing so allows the adversary illegitimate access to the target system, without possessing the requisite credentials. Reflection attacks are of great concern to authentication protocols that rely on a challenge-handshake or similar mechanism. An adversary can impersonate a legitimate user and can gain illegitimate access to the system by successfully mounting a reflection attack during authentication.

## Related CWE (2)

- [CWE-301 — Reflection Attack in an Authentication Protocol](https://cwe.mitre.org/data/definitions/301.html) — Simple authentication protocols are subject to reflection attacks if a malicious user can use the target machine to impersonate a trusted user.
- [CWE-303 — Incorrect Implementation of Authentication Algorithm](https://cwe.mitre.org/data/definitions/303.html) — The requirements for the product dictate the use of an established authentication algorithm, but the implementation of the algorithm is incorrect.

## Prerequisites

- The attacker must have direct access to the target server in order to successfully mount a reflection attack. An intermediate entity, such as a router or proxy, that handles these exchanges on behalf of the attacker inhibits the attackers' ability to attack the authentication protocol.

## Skills required

- [Medium] The attacker needs to have knowledge of observing the protocol exchange and managing the required connections in order to issue and respond to challenges

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges, Bypass Protection Mechanism
- Confidentiality / Read Data

## Mitigations

- The server must initiate the handshake by issuing the challenge. This ensures that the client has to respond before the exchange can move any further
- The use of HMAC to hash the response from the server can also be used to thwart reflection. The server responds by returning its own challenge as well as hashing the client's challenge, its own challenge and the pre-shared secret. Requiring the client to respond with the HMAC of the two challenges ensures that only the possessor of a valid pre-shared secret can successfully hash in the two values.
- Introducing a random nonce with each new connection ensures that the attacker cannot employ two connections to attack the authentication protocol

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
