# D3FEND: Session Termination

<a id="session-termination"></a>

D3FEND tactic: Evict  
Digital artifacts: Session  

Forcefully end all active sessions associated with compromised accounts or devices.

## ATT&CK techniques countered (9)

- [T0822: External Remote Services](https://attack.mitre.org/techniques/T0822): deletes
- [T1021.001: Remote Desktop Protocol](/mitre/techniques/T1021-001.md): deletes. Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a computer using the Remote Desktop Protocol (RDP).
- [T1021.004: SSH](/mitre/techniques/T1021-004.md): deletes. Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into remote machines using Secure Shell (SSH).
- [T1133: External Remote Services](/mitre/techniques/T1133.md): deletes. Adversaries may leverage external-facing remote services to initially access and/or persist within a network.
- [T1134.003: Make and Impersonate Token](/mitre/techniques/T1134-003.md): deletes. Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls.
- [T1199: Trusted Relationship](/mitre/techniques/T1199.md): deletes. Adversaries may breach or otherwise leverage organizations who have access to intended victims.
- [T1563: Remote Service Session Hijacking](/mitre/techniques/T1563.md): deletes. Adversaries may take control of preexisting sessions with remote services to move laterally in an environment.
- [T1563.001: SSH Hijacking](/mitre/techniques/T1563-001.md): deletes. Adversaries may hijack a legitimate user's SSH session to move laterally within an environment.
- [T1563.002: RDP Hijacking](/mitre/techniques/T1563-002.md): deletes. Adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment.

_D3FEND also maps T0807, deprecated in ATT&CK with no successor; not counted above._

## Related pages

- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 5 of these techniques
- [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md), which also counters 5 of these techniques
- [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md), which also counters 5 of these techniques
- [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), which also counters 5 of these techniques
- [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md), which also counters 5 of these techniques
- [Per Host Download-Upload Ratio Analysis](/mitre/d3fend/per-host-download-upload-ratio-analysis.md), which also counters 5 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [The Change Healthcare Attack of 2024: The Largest Healthcare Breach on Record](/case-studies/CHANGE_HEALTHCARE_2024.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
