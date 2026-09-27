# CAPEC-303 — TCP Xmas Scan

<a id="capec-303"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Stable  

An adversary uses a TCP XMAS scan to determine if ports are closed on the target machine. This scan type is accomplished by sending TCP segments with all possible flags set in the packet header, generating packets that are illegal based on RFC 793. The RFC 793 expected behavior is that any TCP segment with an out-of-state Flag sent to an open port is discarded, whereas segments with out-of-state flags sent to closed ports should be handled with a RST in response. This behavior should allow an attacker to scan for closed ports by sending certain types of rule-breaking packets (out of sync or disallowed by the TCB) and detect closed ports via RST packets.

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) — The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The adversary needs logical access to the target network. XMAS scanning requires the use of raw sockets, and thus cannot be performed from some Windows systems (Windows XP SP 2, for example). On Unix and Linux, raw socket manipulations require root privileges.

## Consequences

- Confidentiality / Other
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism, Hide Activities
- Availability / Unreliable Execution

## Mitigations

- Employ a robust network defensive posture that includes a managed IDS/IPS.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
