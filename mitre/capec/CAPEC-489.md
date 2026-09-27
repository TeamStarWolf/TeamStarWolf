# CAPEC-489 — SSL Flood

<a id="capec-489"></a>

**Abstraction:** Standard  
**Status:** Draft  

An adversary may execute a flooding attack using the SSL protocol with the intent to deny legitimate users access to a service by consuming all the available resources on the server side. These attacks take advantage of the asymmetric relationship between the processing power used by the client and the processing power used by the server to create a secure connection. In this manner the attacker can make a large number of HTTPS requests on a low provisioned machine to tie up a disproportionately large number of resources on the server. The clients then continue to keep renegotiating the SSL connection. When multiplied by a large number of attacking machines, this attack can result in a crash or loss of service to legitimate users.

## Mapped ATT&CK techniques (1)

- [T1499.002 — Service Exhaustion Flood](/mitre/techniques/T1499-002.md) — Adversaries may target the different network services provided by systems to conduct a denial of service (DoS).

## Related CWE (1)

- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html) — The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- This type of an attack requires the ability to generate a large amount of SSL traffic to send a target server.

## Mitigations

- To mitigate this type of an attack, an organization can create rule based filters to silently drop connections if too many are attempted in a certain time period.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
