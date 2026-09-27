# CAPEC-488 — HTTP Flood

<a id="capec-488"></a>

**Abstraction:** Standard  
**Status:** Draft  

An adversary may execute a flooding attack using the HTTP protocol with the intent to deny legitimate users access to a service by consuming resources at the application layer such as web services and their infrastructure. These attacks use legitimate session-based HTTP GET requests designed to consume large amounts of a server's resources. Since these are legitimate sessions this attack is very difficult to detect.

## Mapped ATT&CK techniques (1)

- [T1499.002 — Service Exhaustion Flood](/mitre/techniques/T1499-002.md) — Adversaries may target the different network services provided by systems to conduct a denial of service (DoS).

## Related CWE (1)

- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html) — The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- This type of an attack requires the ability to generate a large amount of HTTP traffic to send to a target server.

## Mitigations

- Design: Use a Web Application Firewall (WAF) to help filter out malicious traffic. This can be setup with rules to block IP addresses found in IP reputation databases, which contains lists of known bad IP addresses. Analysts should also monitor when the traffic flow becomes abnormally large, and be able to add on-the-fly rules to block malicious traffic. Special care should be taken to ensure low false positive rates in block rules and functionality should be implemented to allow a legitimate user to resume sending traffic if they have been blocked.
- Hire a third party provider to implement a Web Application Firewall (WAF) for your application. Third party providers have dedicated resources and expertise that could allow them to update rules and prevent HTTP Floods very quickly.
- Design: Use a load balancer such as nginx to prevent small scale HTTP Floods by dispersing traffic between a group of servers.
- Implementation: Make a requesting machine solve some kind of challenge before allowing them to send an HTTP request. This could be a captcha or something similar that works to deter bots.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
