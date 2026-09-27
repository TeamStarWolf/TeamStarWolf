# CAPEC-202 — Create Malicious Client

<a id="capec-202"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

An adversary creates a client application to interface with a target service where the client violates assumptions the service makes about clients. Services that have designated client applications (as opposed to services that use general client applications, such as IMAP or POP mail servers which can interact with any IMAP or POP client) may assume that the client will follow specific procedures.

## Related CWE (1)

- [CWE-602 — Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html) — The product is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.

## Prerequisites

- The targeted service must make assumptions about the behavior of the client application that interacts with it, which can be abused by an adversary.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
