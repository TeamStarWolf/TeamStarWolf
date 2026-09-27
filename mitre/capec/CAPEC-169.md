# CAPEC-169 — Footprinting

<a id="capec-169"></a>

**Abstraction:** Meta  
**Typical severity:** Very Low  
**Likelihood:** High  
**Status:** Stable  

An adversary engages in probing and exploration activities to identify constituents and properties of the target.

## Mapped ATT&CK techniques (3)

- [T1217 — Browser Information Discovery](/mitre/techniques/T1217.md) — Adversaries may enumerate information about browsers to learn more about compromised environments.
- [T1592 — Gather Victim Host Information](/mitre/techniques/T1592.md) — Adversaries may gather information about the victim's hosts that can be used during targeting.
- [T1595 — Active Scanning](/mitre/techniques/T1595.md) — Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) — The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- An application must publicize identifiable information about the system or application through voluntary or involuntary means. Certain identification details of information systems are visible on communication networks (e.g., if an adversary uses a sniffer to inspect the traffic) due to their inherent structure and protocol standards. Any system or network that can be detected can be footprinted. However, some configuration choices may limit the useful information that can be collected during a footprinting attack.

## Skills required

- [Low] The adversary knows how to send HTTP request, run the scan tool.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Keep patches up to date by installing weekly or daily if possible.
- Shut down unnecessary services/ports.
- Change default passwords by choosing strong passwords.
- Curtail unexpected input.
- Encrypt and password-protect sensitive data.
- Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
