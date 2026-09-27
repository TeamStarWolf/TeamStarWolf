# CAPEC-93 — Log Injection-Tampering-Forging

<a id="capec-93"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets the log files of the target host. The attacker injects, manipulates or forges malicious log entries in the log file, allowing them to mislead a log audit, cover traces of attack, or perform other malicious actions. The target host is not properly controlling log access. As a result tainted data is resulting in the log files leading to a failure in accountability, non-repudiatio

## Related CWE (3)

- [CWE-117 — Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [CWE-75 — Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html)
- [CWE-150 — Improper Neutralization of Escape, Meta, or Control Sequences](https://cwe.mitre.org/data/definitions/150.html)

## Prerequisites

- The target host is logging the action and data of the user.
- The target host insufficiently protects access to the logs or logging mechanisms.

## Skills required

- This attack can be as simple as adding extra characters to the logged data (e.g. username). Adding entries is typically easier than removing e

## Mitigations

- Carefully control access to physical log files.
- Do not allow tainted data to be written in the log file without prior input validation. An allowlist may be used to properly validate the data.
- Use synchronization to control the flow of execution.:

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
