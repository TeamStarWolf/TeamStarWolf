# CAPEC-161 — Infrastructure Manipulation

<a id="capec-161"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Status:** Draft  

An attacker exploits characteristics of the infrastructure of a network entity in order to perpetrate attacks or information gathering on network objects or effect a change in the ordinary information flow between network objects. Most often, this involves manipulation of the routing of network messages so, instead of arriving at their proper destination, they are directed towards an entity of the

## Related CWE (1)

- [CWE-923 — Improper Restriction of Communication Channel to Intended Endpoints](https://cwe.mitre.org/data/definitions/923.html)

## Prerequisites

- The targeted client must access the site via infrastructure that the attacker has co-opted and must fail to adequately verify that the communication channel is operating correctly (e.g. by verifying

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
