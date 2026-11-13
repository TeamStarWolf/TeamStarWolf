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

- [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md)
- [Cybercrime and Hacktivism in Four Books: Kingpin, Fatal System Error, We Are Anonymous, The Hacker Crackdown](/case-studies/CYBERCRIME_FOUR_BOOKS.md)
- [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md)
- [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md)
- [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [SSHole: The OpenSSH Authentication Bypass of November 2026 (CVE-2026-123158)](/case-studies/SSHOLE_CVE_2026_123158.md)
- [The ATF Major Incident of 2026: A Case Study](/case-studies/ATF_MAJOR_INCIDENT_2026.md)
- [The Boston Scientific Network Outage of August 2026: A Case Study](/case-studies/BOSTON_SCIENTIFIC_ATTACK_2026.md)
- [The Change Healthcare Attack of 2024: The Largest Healthcare Breach on Record](/case-studies/CHANGE_HEALTHCARE_2024.md)
- [The Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751): A Case Study](/case-studies/CHECK_POINT_VPN_CVE_2026_50751.md)
- [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md)
- [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md)
- [The FBI Surveillance System Breach of 2026: A Case Study](/case-studies/FBI_SURVEILLANCE_SYSTEM_BREACH_2026.md)
- [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md)
- [The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md)
- [The PAN-OS GlobalProtect Authentication Bypass of 2026 (CVE-2026-0257), Qilin and INC Ransomware: A Case Study](/case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md)
- [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md)
- [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)
- [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md)
- [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md)
- [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md)
- [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md)
- [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
