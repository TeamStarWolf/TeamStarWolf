# CAPEC-299: TCP SYN Ping

<a id="capec-299"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Stable  

An adversary uses TCP SYN packets as a means towards host discovery. Typical RFC 793 behavior specifies that when a TCP port is open, a host must respond to an incoming SYN "synchronize" packet by completing stage two of the 'three-way handshake' - by sending an SYN/ACK in response. When a port is closed, RFC 793 behavior is to respond with a RST "reset" packet. This behavior can be used to 'ping' a target to see if it is alive by sending a TCP SYN packet to a port and then looking for a RST or an ACK packet in response.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The ability to send a TCP SYN packet to a remote target. Depending upon the operating system, the ability to craft SYN packets may require elevated privileges.

## Skills required

- [Low] The adversary needs to know how to craft and send protocol commands from the command line or within a tool.

## Consequences

- Confidentiality / Other
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism, Hide Activities

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
