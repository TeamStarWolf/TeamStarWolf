# CAPEC-297 — TCP ACK Ping

<a id="capec-297"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Stable  

An adversary sends a TCP segment with the ACK flag set to a remote host for the purpose of determining if the host is alive. This is one of several TCP 'ping' types. The RFC 793 expected behavior for a service is to respond with a RST 'reset' packet to any unsolicited ACK segment that is not part of an existing connection. So by sending an ACK segment to a port, the adversary can identify that the

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- The ability to send an ACK packet to a remote host and identify the response. Creating the ACK packet without building a full connection requires the use of raw sockets. As a result, it is not possi

## Mitigations

- Leverage stateful firewalls that allow for the rejection of a packet that is not part of an existing connection.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
