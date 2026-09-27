# D3FEND: Restore Configuration

<a id="restore-configuration"></a>

**D3FEND tactic:** Restore  
**Digital artifacts:** Configuration Resource  

Restoring an software configuration.

## ATT&CK techniques countered (55)

- [T0858](https://attack.mitre.org/techniques/T0858) — restores
- [T0868](https://attack.mitre.org/techniques/T0868) — restores
- [T1037.004 — RC Scripts](/mitre/techniques/T1037-004.md) — restores. Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup.
- [T1037.005 — Startup Items](/mitre/techniques/T1037-005.md) — restores. Adversaries may use startup items automatically executed at boot initialization to establish persistence.
- [T1114.003 — Email Forwarding Rule](/mitre/techniques/T1114-003.md) — restores. Adversaries may setup email forwarding rules to collect sensitive information.
- [T1134.005 — SID-History Injection](/mitre/techniques/T1134-005.md) — restores. Adversaries may use SID-History Injection to escalate privileges and bypass access controls.
- [T1137.001 — Office Template Macros](/mitre/techniques/T1137-001.md) — restores. Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system.
- [T1137.002 — Office Test](/mitre/techniques/T1137-002.md) — restores. Adversaries may abuse the Microsoft Office "Office Test" Registry key to obtain persistence on a compromised system.
- [T1137.004 — Outlook Home Page](/mitre/techniques/T1137-004.md) — restores. Adversaries may abuse Microsoft Outlook's Home Page feature to obtain persistence on a compromised system.
- [T1137.005 — Outlook Rules](/mitre/techniques/T1137-005.md) — restores. Adversaries may abuse Microsoft Outlook rules to obtain persistence on a compromised system.
- [T1218.002 — Control Panel](/mitre/techniques/T1218-002.md) — restores. Adversaries may abuse control.exe to proxy execution of malicious payloads.
- [T1222 — File and Directory Permissions Modification](/mitre/techniques/T1222.md) — restores. Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.
- [T1484 — Domain or Tenant Policy Modification](/mitre/techniques/T1484.md) — restores. Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges in centrally managed environments.
- [T1490 — Inhibit System Recovery](/mitre/techniques/T1490.md) — restores. Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.
- [T1518.001 — Security Software Discovery](/mitre/techniques/T1518-001.md) — restores. Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment.
- [T1526 — Cloud Service Discovery](/mitre/techniques/T1526.md) — restores. An adversary may attempt to enumerate the cloud services running on a system after gaining access.
- [T1538 — Cloud Service Dashboard](/mitre/techniques/T1538.md) — restores. An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features.
- [T1546.001 — Change Default File Association](/mitre/techniques/T1546-001.md) — restores. Adversaries may establish persistence by executing malicious content triggered by a file type association.
- [T1546.002 — Screensaver](/mitre/techniques/T1546-002.md) — restores. Adversaries may establish persistence by executing malicious content triggered by user inactivity.
- [T1546.007 — Netsh Helper DLL](/mitre/techniques/T1546-007.md) — restores. Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs.
- [T1546.008 — Accessibility Features](/mitre/techniques/T1546-008.md) — restores. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features.
- [T1546.009 — AppCert DLLs](/mitre/techniques/T1546-009.md) — restores. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes.
- [T1546.010 — AppInit DLLs](/mitre/techniques/T1546-010.md) — restores. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes.
- [T1546.011 — Application Shimming](/mitre/techniques/T1546-011.md) — restores. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims.
- [T1546.014 — Emond](/mitre/techniques/T1546-014.md) — restores. Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond).
- [T1547.001 — Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md) — restores. Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.
- [T1547.002 — Authentication Package](/mitre/techniques/T1547-002.md) — restores. Adversaries may abuse authentication packages to execute DLLs when the system boots.
- [T1547.003 — Time Providers](/mitre/techniques/T1547-003.md) — restores. Adversaries may abuse time providers to execute DLLs when the system boots.
- [T1547.004 — Winlogon Helper DLL](/mitre/techniques/T1547-004.md) — restores. Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in.
- [T1547.005 — Security Support Provider](/mitre/techniques/T1547-005.md) — restores. Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots.
- [T1547.010 — Port Monitors](/mitre/techniques/T1547-010.md) — restores. Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation.
- [T1548.001 — Setuid and Setgid](/mitre/techniques/T1548-001.md) — restores. An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context.
- [T1548.002 — Bypass User Account Control](/mitre/techniques/T1548-002.md) — restores. Adversaries may bypass UAC mechanisms to elevate process privileges on system.
- [T1548.005 — Temporary Elevated Cloud Access](/mitre/techniques/T1548-005.md) — restores. Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources.
- [T1552.005 — Cloud Instance Metadata API](/mitre/techniques/T1552-005.md) — restores. Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data.
- [T1552.006 — Group Policy Preferences](/mitre/techniques/T1552-006.md) — restores. Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP).
- [T1553.003 — SIP and Trust Provider Hijacking](/mitre/techniques/T1553-003.md) — restores. Adversaries may tamper with SIP and trust provider components to mislead the operating system and application control tools when conducting signature validation checks.
- [T1556.002 — Password Filter DLL](/mitre/techniques/T1556-002.md) — restores. Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated.
- [T1556.009 — Conditional Access Policies](/mitre/techniques/T1556-009.md) — restores. Adversaries may disable or modify conditional access policies to enable persistent access to compromised accounts.
- [T1562.002 — Disable Windows Event Logging](/mitre/techniques/T1562-002.md) — restores. Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits.
- [T1562.003 — Impair Command History Logging](/mitre/techniques/T1562-003.md) — restores. Adversaries may impair command history logging to hide commands they run on a compromised system.
- [T1562.004 — Disable or Modify System Firewall](/mitre/techniques/T1562-004.md) — restores. Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage.
- [T1562.007 — Disable or Modify Cloud Firewall](/mitre/techniques/T1562-007.md) — restores. Adversaries may disable or modify a firewall within a cloud environment to bypass controls that limit access to cloud resources.
- [T1562.008 — Disable or Modify Cloud Logs](/mitre/techniques/T1562-008.md) — restores. An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection.
- [T1562.009 — Safe Mode Boot](/mitre/techniques/T1562-009.md) — restores. Adversaries may abuse Windows safe mode to disable endpoint defenses.
- [T1564.008 — Email Hiding Rules](/mitre/techniques/T1564-008.md) — restores. Adversaries may use email rules to hide inbound emails in a compromised user's mailbox.
- [T1574.011 — Services Registry Permissions Weakness](/mitre/techniques/T1574-011.md) — restores. Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
- [T1574.012 — COR_PROFILER](/mitre/techniques/T1574-012.md) — restores. Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the.NET CLR.
- [T1578.002 — Create Cloud Instance](/mitre/techniques/T1578-002.md) — restores. An adversary may create a new instance or virtual machine (VM) within the compute service of a cloud account to evade defenses.
- [T1578.003 — Delete Cloud Instance](/mitre/techniques/T1578-003.md) — restores. An adversary may delete a cloud instance after they have performed malicious activities in an attempt to evade detection and remove evidence of their presence.
- [T1578.004 — Revert Cloud Instance](/mitre/techniques/T1578-004.md) — restores. An adversary may revert changes made to a cloud instance after they have performed malicious activities in attempt to evade detection and remove evidence of their presence.
- [T1578.005 — Modify Cloud Compute Configurations](/mitre/techniques/T1578-005.md) — restores. Adversaries may modify settings that directly affect the size, locations, and resources available to cloud compute infrastructure in order to evade defenses.
- [T1614 — System Location Discovery](/mitre/techniques/T1614.md) — restores. Adversaries may gather information in an attempt to calculate the geographical location of a victim host.
- [T1615 — Group Policy Discovery](/mitre/techniques/T1615.md) — restores. Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or…
- [T1666 — Modify Cloud Resource Hierarchy](/mitre/techniques/T1666.md) — restores. Adversaries may attempt to modify hierarchical structures in infrastructure-as-a-service (IaaS) environments in order to evade defenses.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
