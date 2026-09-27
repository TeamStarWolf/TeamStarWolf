# CAPEC-596 — TCP RST Injection

<a id="capec-596"></a>

**Abstraction:** Detailed  
**Status:** Draft  

An adversary injects one or more TCP RST packets to a target after the target has made a HTTP GET request. The goal of this attack is to have the target and/or destination web server terminate the TCP connection.

## Related CWE (1)

- [CWE-940 — Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html) — The product establishes a communication channel to handle an incoming request that has been initiated by an actor, but it does not properly verify that the request is coming from the expected origin.

## Prerequisites

- An On/In Path Device

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
