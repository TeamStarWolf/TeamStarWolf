# D3FEND: Connection Attempt Analysis

<a id="connection-attempt-analysis"></a>

D3FEND tactic: Detect  
Digital artifacts: Intranet Network Traffic  

Analyzing failed connections in a network to detect unauthorized activity.

## ATT&CK techniques countered (18)

- [T0866: Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866): analyzes
- [T0884: Connection Proxy](https://attack.mitre.org/techniques/T0884): analyzes
- [T0886: Remote Services](https://attack.mitre.org/techniques/T0886): analyzes
- [T1003.006: DCSync](/mitre/techniques/T1003-006.md): analyzes. Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique called DCSync.
- [T1021: Remote Services](/mitre/techniques/T1021.md): analyzes. Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service that accepts remote connections, such as telnet, SSH, and VNC.
- [T1047: Windows Management Instrumentation](/mitre/techniques/T1047.md): analyzes. Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.
- [T1090.001: Internal Proxy](/mitre/techniques/T1090-001.md): analyzes. Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment.
- [T1098.001: Additional Cloud Credentials](/mitre/techniques/T1098-001.md): analyzes. Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.
- [T1110.003: Password Spraying](/mitre/techniques/T1110-003.md): analyzes. Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.
- [T1110.004: Credential Stuffing](/mitre/techniques/T1110-004.md): analyzes. Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap.
- [T1197: BITS Jobs](/mitre/techniques/T1197.md): analyzes. Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks.
- [T1199: Trusted Relationship](/mitre/techniques/T1199.md): analyzes. Adversaries may breach or otherwise leverage organizations who have access to intended victims.
- [T1207: Rogue Domain Controller](/mitre/techniques/T1207.md): analyzes. Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data.
- [T1210: Exploitation of Remote Services](/mitre/techniques/T1210.md): analyzes. Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.
- [T1546.003: Windows Management Instrumentation Event Subscription](/mitre/techniques/T1546-003.md): analyzes. Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription.
- [T1546.008: Accessibility Features](/mitre/techniques/T1546-008.md): analyzes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features.
- [T1557.001: Name Resolution Poisoning and SMB Relay](/mitre/techniques/T1557-001.md): analyzes. By responding to LLMNR/NBT-NS/mDNS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system.
- [T1570: Lateral Tool Transfer](/mitre/techniques/T1570.md): analyzes. Adversaries may transfer tools or other files between systems in a compromised environment.

## Related pages

- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 18 of these techniques
- [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md), which also counters 18 of these techniques
- [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md), which also counters 18 of these techniques
- [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), which also counters 18 of these techniques
- [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md), which also counters 18 of these techniques
- [Per Host Download-Upload Ratio Analysis](/mitre/d3fend/per-host-download-upload-ratio-analysis.md), which also counters 18 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986](/case-studies/CUCKOOS_EGG_1986.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)
- [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
