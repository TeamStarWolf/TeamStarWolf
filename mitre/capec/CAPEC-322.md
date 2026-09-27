# CAPEC-322 — TCP (ISN) Greatest Common Divisor Probe

<a id="capec-322"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Medium  
**Status:** Stable  

This OS fingerprinting probe sends a number of TCP SYN packets to an open port of a remote machine. The Initial Sequence Number (ISN) in each of the SYN/ACK response packets is analyzed to determine the smallest number that the target host uses when incrementing sequence numbers. This information can be useful for identifying an operating system because particular operating systems and versions in

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- The ability to monitor and interact with network communications.Access to at least one host, and the privileges to interface with the network interface card.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
