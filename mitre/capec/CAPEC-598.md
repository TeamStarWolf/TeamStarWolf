# CAPEC-598: DNS Spoofing

<a id="capec-598"></a>

Abstraction: Detailed  
Status: Draft  

An adversary sends a malicious ("NXDOMAIN" ("No such domain") code, or DNS A record) response to a target's route request before a legitimate resolver can. This technique requires an On-path or In-path device that can monitor and respond to the target's DNS requests. This attack differs from BGP Tampering in that it directly responds to requests made by the target instead of polluting the routing the target's infrastructure uses.

## Prerequisites

- On/In Path Device

## Skills required

- [Low] To distribute email

## Mitigations

- Design: Avoid dependence on DNS
- Design: Include "hosts file"/IP address in the application
- Implementation: Utilize a .onion domain with Tor support
- Implementation: DNSSEC
- Implementation: DNS-hold-open

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
