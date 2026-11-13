# D3FEND: Process Spawn Analysis

<a id="process-spawn-analysis"></a>

D3FEND tactic: Detect  
Digital artifacts: Create Process, Process  

Analyzing spawn arguments or attributes of a process to detect processes that are unauthorized.

## ATT&CK techniques countered (48)

- [T0806: Brute Force I/O](https://attack.mitre.org/techniques/T0806): analyzes
- [T0813: Denial of Control](https://attack.mitre.org/techniques/T0813): analyzes
- [T0814: Denial of Service](https://attack.mitre.org/techniques/T0814): analyzes
- [T0819: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T0819): analyzes
- [T0821: Modify Controller Tasking](https://attack.mitre.org/techniques/T0821): analyzes
- [T0823: Graphical User Interface](https://attack.mitre.org/techniques/T0823): analyzes
- [T0846: Remote System Discovery](https://attack.mitre.org/techniques/T0846): analyzes
- [T0863: User Execution](https://attack.mitre.org/techniques/T0863): analyzes
- [T0878: Alarm Suppression](https://attack.mitre.org/techniques/T0878): analyzes
- [T0888: Remote System Information Discovery](https://attack.mitre.org/techniques/T0888): analyzes
- [T0894: System Binary Proxy Execution](https://attack.mitre.org/techniques/T0894): analyzes
- [T0895: Autorun Image](https://attack.mitre.org/techniques/T0895): analyzes
- [T1003.001: LSASS Memory](/mitre/techniques/T1003-001.md): analyzes. Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).
- [T1003.002: Security Account Manager](/mitre/techniques/T1003-002.md): analyzes. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored.
- [T1003.004: LSA Secrets](/mitre/techniques/T1003-004.md): analyzes. Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts.
- [T1007: System Service Discovery](/mitre/techniques/T1007.md): analyzes. Adversaries may try to gather information about registered local system services.
- [T1010: Application Window Discovery](/mitre/techniques/T1010.md): analyzes. Adversaries may attempt to get a listing of open application windows.
- [T1016: System Network Configuration Discovery](/mitre/techniques/T1016.md): analyzes. Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems.
- [T1018: Remote System Discovery](/mitre/techniques/T1018.md): analyzes. Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system.
- [T1033: System Owner/User Discovery](/mitre/techniques/T1033.md): analyzes. Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.
- [T1047: Windows Management Instrumentation](/mitre/techniques/T1047.md): analyzes. Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.
- [T1053: Scheduled Task/Job](/mitre/techniques/T1053.md): analyzes. Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.
- [T1053.005: Scheduled Task](/mitre/techniques/T1053-005.md): analyzes. Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.
- [T1055.004: Asynchronous Procedure Call](/mitre/techniques/T1055-004.md): analyzes. Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges.
- [T1055.013: Process Doppelgänging](/mitre/techniques/T1055-013.md): analyzes. Adversaries may inject malicious code into process via process doppelgänging in order to evade process-based defenses as well as possibly elevate privileges.
- [T1057: Process Discovery](/mitre/techniques/T1057.md): analyzes. Adversaries may attempt to get information about running processes on a system.
- [T1082: System Information Discovery](/mitre/techniques/T1082.md): analyzes. An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.
- [T1124: System Time Discovery](/mitre/techniques/T1124.md): analyzes. An adversary may gather the system time and/or time zone settings from a local or remote system.
- [T1134.004: Parent PID Spoofing](/mitre/techniques/T1134-004.md): analyzes. Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges.
- [T1140: Deobfuscate/Decode Files or Information](/mitre/techniques/T1140.md): analyzes. Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis.
- [T1212: Exploitation for Credential Access](/mitre/techniques/T1212.md): analyzes. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.
- [T1218.001: Compiled HTML File](/mitre/techniques/T1218-001.md): analyzes. Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code.
- [T1218.002: Control Panel](/mitre/techniques/T1218-002.md): analyzes. Adversaries may abuse control.exe to proxy execution of malicious payloads.
- [T1218.003: CMSTP](/mitre/techniques/T1218-003.md): analyzes. Adversaries may abuse CMSTP to proxy execution of malicious code.
- [T1218.005: Mshta](/mitre/techniques/T1218-005.md): analyzes. Adversaries may abuse mshta.exe to proxy execution of malicious.hta files and Javascript or VBScript through a trusted Windows utility.
- [T1218.011: Rundll32](/mitre/techniques/T1218-011.md): analyzes. Adversaries may abuse rundll32.exe to proxy execution of malicious code.
- [T1220: XSL Script Processing](/mitre/techniques/T1220.md): analyzes. Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files.
- [T1505.001: SQL Stored Procedures](/mitre/techniques/T1505-001.md): analyzes. Adversaries may abuse SQL stored procedures to establish persistent access to systems.
- [T1505.002: Transport Agent](/mitre/techniques/T1505-002.md): analyzes. Adversaries may abuse Microsoft transport agents to establish persistent access to systems.
- [T1505.003: Web Shell](/mitre/techniques/T1505-003.md): analyzes. Adversaries may backdoor web servers with web shells to establish persistent access to systems.
- [T1546.007: Netsh Helper DLL](/mitre/techniques/T1546-007.md): analyzes. Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs.
- [T1546.009: AppCert DLLs](/mitre/techniques/T1546-009.md): analyzes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes.
- [T1546.010: AppInit DLLs](/mitre/techniques/T1546-010.md): analyzes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes.
- [T1548.002: Bypass User Account Control](/mitre/techniques/T1548-002.md): analyzes. Adversaries may bypass UAC mechanisms to elevate process privileges on system.
- [T1550: Use Alternate Authentication Material](/mitre/techniques/T1550.md): analyzes. Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.
- [T1556: Modify Authentication Process](/mitre/techniques/T1556.md): analyzes. Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.
- [T1621: Multi-Factor Authentication Request Generation](/mitre/techniques/T1621.md): analyzes. Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.
- [T1685: Disable or Modify Tools](/mitre/techniques/T1685.md): analyzes (D3FEND maps the revoked predecessor T1562.001). Adversaries may disable, degrade, or tamper with security tools or applications (e.g., endpoint detection and response (EDR) tools, intrusion detection systems (IDS), antivirus, logging agents, sensors, etc.) to impair or reduce visibility of defensive capabilities.

## Related pages

- [Hardware-based Process Isolation](/mitre/d3fend/hardware-based-process-isolation.md), which also counters 48 of these techniques
- [System Call Filtering](/mitre/d3fend/system-call-filtering.md), which also counters 48 of these techniques
- [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md), which also counters 30 of these techniques
- [Executable Denylisting](/mitre/d3fend/executable-denylisting.md), which also counters 30 of these techniques
- [System Call Analysis](/mitre/d3fend/system-call-analysis.md), which also counters 29 of these techniques
- [Application-based Process Isolation](/mitre/d3fend/application-based-process-isolation.md), which also counters 22 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [Collabora Built-in CODE Server (richdocumentscode), CVE-2026-110447: Lab-Verified Exposure and Fix](/case-studies/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md)
- [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md)
- [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md)
- [Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/GHOSTCAT_CVE_2020_1938.md)
- [GitLab, CVE-2026-97229: Lab-Verified Exposure and Fix](/case-studies/GITLAB_CVE_2026_97229.md)
- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md)
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)
- [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md)
- [Oracle PeopleSoft CVE-2026-35273 and the ShinyHunters Mass Exploitation of 2026: A Case Study](/case-studies/ORACLE_PEOPLESOFT_SHINYHUNTERS_2026.md)
- [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md)
- [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md)
- [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)
- [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md)
- [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md)
- [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
