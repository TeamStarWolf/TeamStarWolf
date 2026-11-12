# D3FEND: Web Session Access Mediation

<a id="web-session-access-mediation"></a>

D3FEND tactic: Isolate  
Digital artifacts: Service Application Process  

Web session access mediation secures user sessions in web applications by employing robust authentication and integrity validation, along with adaptive threat mitigation techniques, to ensure that access to web resources is authorized and protected from session-related attacks.

## ATT&CK techniques countered (14)

- [T0806: Brute Force I/O](https://attack.mitre.org/techniques/T0806): isolates
- [T0813: Denial of Control](https://attack.mitre.org/techniques/T0813): isolates
- [T0814: Denial of Service](https://attack.mitre.org/techniques/T0814): isolates
- [T0819: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T0819): isolates
- [T0821: Modify Controller Tasking](https://attack.mitre.org/techniques/T0821): isolates
- [T0878: Alarm Suppression](https://attack.mitre.org/techniques/T0878): isolates
- [T1003.001: LSASS Memory](/mitre/techniques/T1003-001.md): isolates. Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).
- [T1003.002: Security Account Manager](/mitre/techniques/T1003-002.md): isolates. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored.
- [T1033: System Owner/User Discovery](/mitre/techniques/T1033.md): isolates. Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.
- [T1212: Exploitation for Credential Access](/mitre/techniques/T1212.md): isolates. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.
- [T1505.002: Transport Agent](/mitre/techniques/T1505-002.md): isolates. Adversaries may abuse Microsoft transport agents to establish persistent access to systems.
- [T1550: Use Alternate Authentication Material](/mitre/techniques/T1550.md): isolates. Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.
- [T1556: Modify Authentication Process](/mitre/techniques/T1556.md): isolates. Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.
- [T1621: Multi-Factor Authentication Request Generation](/mitre/techniques/T1621.md): isolates. Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.

## Related pages

- [Application-based Process Isolation](/mitre/d3fend/application-based-process-isolation.md), which also counters 14 of these techniques
- [Hardware-based Process Isolation](/mitre/d3fend/hardware-based-process-isolation.md), which also counters 14 of these techniques
- [Host Reboot](/mitre/d3fend/host-reboot.md), which also counters 14 of these techniques
- [Host Shutdown](/mitre/d3fend/host-shutdown.md), which also counters 14 of these techniques
- [Kernel-based Process Isolation](/mitre/d3fend/kernel-based-process-isolation.md), which also counters 14 of these techniques
- [Process Lineage Analysis](/mitre/d3fend/process-lineage-analysis.md), which also counters 14 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md)
- [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md)
- [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md)
- [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
