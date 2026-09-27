# CAPEC-268 — Audit Log Manipulation

<a id="capec-268"></a>

**Abstraction:** Standard  
**Status:** Draft  

The attacker injects, manipulates, deletes, or forges malicious log entries into the log file, in an attempt to mislead an audit of the log file or cover tracks of an attack. Due to either insufficient access controls of the log files or the logging mechanism, the attacker is able to perform such actions.

## Mapped ATT&CK techniques (4)

- [T1070 — Indicator Removal](/mitre/techniques/T1070.md)
- [T1562.002 — Disable Windows Event Logging](/mitre/techniques/T1562-002.md)
- [T1562.003 — Impair Command History Logging](/mitre/techniques/T1562-003.md)
- [T1562.008 — Disable or Modify Cloud Logs](/mitre/techniques/T1562-008.md)

## Related CWE (1)

- [CWE-117 — Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

## Prerequisites

- The target host is logging the action and data of the user.
- The target host insufficiently protects access to the logs or logging mechanisms.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
