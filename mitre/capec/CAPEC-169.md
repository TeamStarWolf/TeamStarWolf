# CAPEC-169 — Footprinting

<a id="capec-169"></a>

**Abstraction:** Meta  
**Typical severity:** Very Low  
**Likelihood:** High  
**Status:** Stable  

An adversary engages in probing and exploration activities to identify constituents and properties of the target.

## Mapped ATT&CK techniques (3)

- [T1217 — Browser Information Discovery](/mitre/techniques/T1217.md)
- [T1592 — Gather Victim Host Information](/mitre/techniques/T1592.md)
- [T1595 — Active Scanning](/mitre/techniques/T1595.md)

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- An application must publicize identifiable information about the system or application through voluntary or involuntary means. Certain identification details of information systems are visible on co

## Skills required

- The adversary knows how to send HTTP request, run the scan tool.:LEVEL:Low

## Mitigations

- Keep patches up to date by installing weekly or daily if possible.
- Shut down unnecessary services/ports.
- Change default passwords by choosing strong passwords.
- Curtail unexpected input.
- Encrypt and password-protect sensitive data.
- Avoid includ

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
