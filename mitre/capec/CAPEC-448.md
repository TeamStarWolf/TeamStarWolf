# CAPEC-448 — Embed Virus into DLL

<a id="capec-448"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary tampers with a DLL and embeds a computer virus into gaps between legitimate machine instructions. These gaps may be the result of compiler optimizations that pad memory blocks for performance gains. The embedded virus then attempts to infect any machine which interfaces with the product, and possibly steal private data or eavesdrop.

## Mapped ATT&CK techniques (1)

- [T1027.009 — Embedded Payloads](/mitre/techniques/T1027-009.md) — Adversaries may embed payloads within other files to conceal malicious content from defenses.

## Related CWE (1)

- [CWE-506 — Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html) — The product contains code that appears to be malicious in nature.

## Prerequisites

- Access to the software currently deployed at a victim location. This access is often obtained by leveraging another attack pattern to gain permissions that the adversary wouldn't normally have.

## Consequences

- Authorization / Execute Unauthorized Commands

## Mitigations

- Leverage anti-virus products to detect and quarantine software with known virus.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
