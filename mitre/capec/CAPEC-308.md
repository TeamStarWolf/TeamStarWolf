# CAPEC-308 — UDP Scan

<a id="capec-308"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Stable  

An adversary engages in UDP scanning to gather information about UDP port status on the target system. UDP scanning methods involve sending a UDP datagram to the target port and looking for evidence that the port is closed. Open UDP ports usually do not respond to UDP datagrams as there is no stateful mechanism within the protocol that requires building or establishing a session. Responses to UDP

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- The ability to send UDP datagrams to a host and receive ICMP error messages from that host. In cases where particular types of ICMP messaging is disallowed, the reliability of UDP scanning drops off

## Mitigations

- Firewalls or ACLs which block egress ICMP error types effectively prevent UDP scans from returning any useful information.
- UDP scanning is complicated by rate limiting mechanisms governing ICMP error messages.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
