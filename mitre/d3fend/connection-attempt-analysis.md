# D3FEND: Connection Attempt Analysis

<a id="connection-attempt-analysis"></a>

**D3FEND tactic:** Detect  
**Digital artifacts:** Intranet Network Traffic  

Analyzing failed connections in a network to detect unauthorized activity.

## ATT&CK techniques countered (18)

- [T0866](https://attack.mitre.org/techniques/T0866) — analyzes
- [T0884](https://attack.mitre.org/techniques/T0884) — analyzes
- [T0886](https://attack.mitre.org/techniques/T0886) — analyzes
- [T1003.006 — DCSync](/mitre/techniques/T1003-006.md) — analyzes. Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain…
- [T1021 — Remote Services](/mitre/techniques/T1021.md) — analyzes. Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service that accepts remote connections, such as telnet, SSH, and VNC.
- [T1047 — Windows Management Instrumentation](/mitre/techniques/T1047.md) — analyzes. Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.
- [T1090.001 — Internal Proxy](/mitre/techniques/T1090-001.md) — analyzes. Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment.
- [T1098.001 — Additional Cloud Credentials](/mitre/techniques/T1098-001.md) — analyzes. Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.
- [T1110.003 — Password Spraying](/mitre/techniques/T1110-003.md) — analyzes. Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.
- [T1110.004 — Credential Stuffing](/mitre/techniques/T1110-004.md) — analyzes. Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap.
- [T1197 — BITS Jobs](/mitre/techniques/T1197.md) — analyzes. Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks.
- [T1199 — Trusted Relationship](/mitre/techniques/T1199.md) — analyzes. Adversaries may breach or otherwise leverage organizations who have access to intended victims.
- [T1207 — Rogue Domain Controller](/mitre/techniques/T1207.md) — analyzes. Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data.
- [T1210 — Exploitation of Remote Services](/mitre/techniques/T1210.md) — analyzes. Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.
- [T1546.003 — Windows Management Instrumentation Event Subscription](/mitre/techniques/T1546-003.md) — analyzes. Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription.
- [T1546.008 — Accessibility Features](/mitre/techniques/T1546-008.md) — analyzes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features.
- [T1557.001 — Name Resolution Poisoning and SMB Relay](/mitre/techniques/T1557-001.md) — analyzes. By responding to LLMNR/NBT-NS/mDNS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system.
- [T1570 — Lateral Tool Transfer](/mitre/techniques/T1570.md) — analyzes. Adversaries may transfer tools or other files between systems in a compromised environment.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
