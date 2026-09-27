# CAPEC-488 — HTTP Flood

<a id="capec-488"></a>

**Abstraction:** Standard  
**Status:** Draft  

An adversary may execute a flooding attack using the HTTP protocol with the intent to deny legitimate users access to a service by consuming resources at the application layer such as web services and their infrastructure. These attacks use legitimate session-based HTTP GET requests designed to consume large amounts of a server's resources. Since these are legitimate sessions this attack is very d

## Mapped ATT&CK techniques (1)

- [T1499.002 — Service Exhaustion Flood](/mitre/techniques/T1499-002.md)

## Related CWE (1)

- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)

## Prerequisites

- This type of an attack requires the ability to generate a large amount of HTTP traffic to send to a target server.

## Mitigations

- Design: Use a Web Application Firewall (WAF) to help filter out malicious traffic. This can be setup with rules to block IP addresses found in IP reputation databases, which contains lists of known bad IP addresses. Analysts should also monitor whe

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
