# CAPEC-208 — Removing/short-circuiting 'Purse' logic: removing/mutating 'cash' decrements

<a id="capec-208"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An attacker removes or modifies the logic on a client associated with monetary calculations resulting in incorrect information being sent to the server. A server may rely on a client to correctly compute monetary information. For example, a server might supply a price for an item and then rely on the client to correctly compute the total cost of a purchase given the number of items the user is buy

## Related CWE (1)

- [CWE-602 — Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

## Prerequisites

- The targeted server must rely on the client to correctly perform monetary calculations and must fail to detect errors in these calculations.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
