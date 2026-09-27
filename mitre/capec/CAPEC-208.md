# CAPEC-208 — Removing/short-circuiting 'Purse' logic: removing/mutating 'cash' decrements

<a id="capec-208"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An attacker removes or modifies the logic on a client associated with monetary calculations resulting in incorrect information being sent to the server. A server may rely on a client to correctly compute monetary information. For example, a server might supply a price for an item and then rely on the client to correctly compute the total cost of a purchase given the number of items the user is buying. If the attacker can remove or modify the logic that controls these calculations, they can return incorrect values to the server. The attacker can use this to make purchases for a fraction of the legitimate cost or otherwise avoid correct billing for activities.

## Related CWE (1)

- [CWE-602 — Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html) — The product is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.

## Prerequisites

- The targeted server must rely on the client to correctly perform monetary calculations and must fail to detect errors in these calculations.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
