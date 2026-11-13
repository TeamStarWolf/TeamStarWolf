# CAPEC-268: Audit Log Manipulation

<a id="capec-268"></a>

Abstraction: Standard  
Status: Draft  

The attacker injects, manipulates, deletes, or forges malicious log entries into the log file, in an attempt to mislead an audit of the log file or cover tracks of an attack. Due to either insufficient access controls of the log files or the logging mechanism, the attacker is able to perform such actions.

## Mapped ATT&CK techniques (4)

- [T1070: Indicator Removal](/mitre/techniques/T1070.md): Adversaries may selectively delete or modify artifacts generated to reduce indications of their presence and blend in with legitimate activity.
- [T1562.002: Disable Windows Event Logging](/mitre/techniques/T1562-002.md): Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits.
- [T1562.003: Impair Command History Logging](/mitre/techniques/T1562-003.md): Adversaries may impair command history logging to hide commands they run on a compromised system.
- [T1562.008: Disable or Modify Cloud Logs](/mitre/techniques/T1562-008.md): An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection.

## Related CWE (1)

- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html): The product constructs a log message from external input, but it does not neutralize or incorrectly neutralizes special elements when the message is written to a log file.

## Prerequisites

- The target host is logging the action and data of the user.
- The target host insufficiently protects access to the logs or logging mechanisms.

## Related pages

- [T1685.001: Disable or Modify Windows Event Log](/mitre/techniques/T1685-001.md), whose ATT&CK profile lists this pattern
- [T1685.002: Disable or Modify Cloud Log](/mitre/techniques/T1685-002.md), whose ATT&CK profile lists this pattern
- [T1690: Prevent Command History Logging](/mitre/techniques/T1690.md), whose ATT&CK profile lists this pattern
- [CAPEC-81: Web Server Logs Tampering](/mitre/capec/CAPEC-81.md), also related to CWE-117
- [CAPEC-93: Log Injection-Tampering-Forging](/mitre/capec/CAPEC-93.md), also related to CWE-117
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md)
- [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md)
- [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md)
- [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
