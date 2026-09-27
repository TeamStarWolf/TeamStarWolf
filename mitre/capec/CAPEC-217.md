# CAPEC-217 — Exploiting Incorrectly Configured SSL/TLS

<a id="capec-217"></a>

**Abstraction:** Standard  
**Likelihood:** Low  
**Status:** Draft  

An adversary takes advantage of incorrectly configured SSL/TLS communications that enables access to data intended to be encrypted. The adversary may also use this type of attack to inject commands or other traffic into the encrypted stream to cause compromise of either the client or server.

## Related CWE (1)

- [CWE-201 — Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html)

## Prerequisites

- Access to the client/server stream.

## Skills required

- The adversary needs real-time access to network traffic in such a manner that the adversary can grab needed information from the SSL stream, p

## Mitigations

- Do not use SSL, as all SSL versions have been broken and should not be used. If TLS is not an option for the client or server, consider setting timeouts on SSL sessions to extremely low values to lessen the potential impact.
- Only use TLS version 1

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
