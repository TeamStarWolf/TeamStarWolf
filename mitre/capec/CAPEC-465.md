# CAPEC-465 — Transparent Proxy Abuse

<a id="capec-465"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

A transparent proxy serves as an intermediate between the client and the internet at large. It intercepts all requests originating from the client and forwards them to the correct location. The proxy also intercepts all responses to the client and forwards these to the client. All of this is done in a manner transparent to the client.

## Mapped ATT&CK techniques (1)

- [T1090.001 — Internal Proxy](/mitre/techniques/T1090-001.md)

## Related CWE (1)

- [CWE-441 — Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

## Prerequisites

- Transparent proxy is usedVulnerable configuration of network topology involving the transparent proxy (e.g., no NAT happening between the client and the proxy)Execution of malicious Flash or Applet

## Skills required

- Creating malicious Flash or Applet to open a cross-domain socket connection to a remote system:LEVEL:Medium

## Mitigations

- Design: Ensure that the transparent proxy uses an actual network layer IP address for routing requests. On the transparent proxy, disable the use of routing based on address information in the HTTP host header.
- Configuration: Disable in the browse

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
