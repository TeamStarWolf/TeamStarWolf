# D3FEND: Operational Process Monitoring

<a id="operational-process-monitoring"></a>

D3FEND tactic: Detect  
Digital artifacts: Event Log, OT Process Data Historian  

Monitoring physical parameters and operator actions related to an operational environment.

## ATT&CK techniques countered (14)

- [T0811: Data from Information Repositories](https://attack.mitre.org/techniques/T0811): uses
- [T1003.006: DCSync](/mitre/techniques/T1003-006.md): monitors. Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique called DCSync.
- [T1070.003: Clear Command History](/mitre/techniques/T1070-003.md): monitors. In addition to clearing system logs, an adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion.
- [T1110.001: Password Guessing](/mitre/techniques/T1110-001.md): monitors. Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.
- [T1110.003: Password Spraying](/mitre/techniques/T1110-003.md): monitors. Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.
- [T1110.004: Credential Stuffing](/mitre/techniques/T1110-004.md): monitors. Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap.
- [T1134.002: Create Process with Token](/mitre/techniques/T1134-002.md): monitors. Adversaries may create a new process with an existing token to escalate privileges and bypass access controls.
- [T1134.003: Make and Impersonate Token](/mitre/techniques/T1134-003.md): monitors. Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls.
- [T1140: Deobfuscate/Decode Files or Information](/mitre/techniques/T1140.md): monitors. Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis.
- [T1187: Forced Authentication](/mitre/techniques/T1187.md): monitors. Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.
- [T1546.003: Windows Management Instrumentation Event Subscription](/mitre/techniques/T1546-003.md): monitors. Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription.
- [T1546.005: Trap](/mitre/techniques/T1546-005.md): monitors. Adversaries may establish persistence by executing malicious content triggered by an interrupt signal.
- [T1548.003: Sudo and Sudo Caching](/mitre/techniques/T1548-003.md): monitors. Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges.
- [T1685.005: Clear Windows Event Logs](/mitre/techniques/T1685-005.md): monitors (D3FEND maps the revoked predecessor T1070.001). Adversaries may clear Windows Event Logs to hide the activity of an intrusion.

## Related pages

- [Application Exception Monitoring](/mitre/d3fend/application-exception-monitoring.md), which also counters 13 of these techniques
- [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), which also counters 5 of these techniques
- [Administrative Network Activity Analysis](/mitre/d3fend/administrative-network-activity-analysis.md), which also counters 4 of these techniques
- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 4 of these techniques
- [Authentication Cache Invalidation](/mitre/d3fend/authentication-cache-invalidation.md), which also counters 4 of these techniques
- [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md), which also counters 4 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
