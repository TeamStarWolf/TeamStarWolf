# D3FEND: Restore Database

<a id="restore-database"></a>

D3FEND tactic: Restore  
Digital artifacts: Database  

Restoring the data in a database.

## ATT&CK techniques countered (23)

- [T0894](https://attack.mitre.org/techniques/T0894): restores
- [T1003.002: Security Account Manager](/mitre/techniques/T1003-002.md): restores. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored.
- [T1003.004: LSA Secrets](/mitre/techniques/T1003-004.md): restores. Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts.
- [T1003.008: /etc/passwd and /etc/shadow](/mitre/techniques/T1003-008.md): restores. Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking.
- [T1012: Query Registry](/mitre/techniques/T1012.md): restores. Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.
- [T1033: System Owner/User Discovery](/mitre/techniques/T1033.md): restores. Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.
- [T1112: Modify Registry](/mitre/techniques/T1112.md): restores. Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution.
- [T1137.006: Add-ins](/mitre/techniques/T1137-006.md): restores. Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system.
- [T1207: Rogue Domain Controller](/mitre/techniques/T1207.md): restores. Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data.
- [T1213.003: Code Repositories](/mitre/techniques/T1213-003.md): restores. Adversaries may leverage code repositories to collect valuable information.
- [T1218.014: MMC](/mitre/techniques/T1218-014.md): restores. Adversaries may abuse mmc.exe to proxy execution of malicious.msc files.
- [T1543.003: Windows Service](/mitre/techniques/T1543-003.md): restores. Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence.
- [T1546.012: Image File Execution Options Injection](/mitre/techniques/T1546-012.md): restores. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers.
- [T1546.015: Component Object Model Hijacking](/mitre/techniques/T1546-015.md): restores. Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects.
- [T1548.004: Elevated Execution with Prompt](/mitre/techniques/T1548-004.md): restores. Adversaries may leverage the <code>AuthorizationExecuteWithPrivileges</code> API to escalate privileges by prompting the user for credentials.
- [T1552.002: Credentials in Registry](/mitre/techniques/T1552-002.md): restores. Adversaries may search the Registry on compromised systems for insecurely stored credentials.
- [T1555: Credentials from Password Stores](/mitre/techniques/T1555.md): restores. Adversaries may search for common password storage locations to obtain user credentials.
- [T1555.001: Keychain](/mitre/techniques/T1555-001.md): restores. Adversaries may acquire credentials from Keychain.
- [T1555.002: Securityd Memory](/mitre/techniques/T1555-002.md): restores. An adversary with root access may gather credentials by reading `securityd`’s memory.
- [T1555.003: Credentials from Web Browsers](/mitre/techniques/T1555-003.md): restores. Adversaries may acquire credentials from web browsers by reading files specific to the target browser.
- [T1564.003: Hidden Window](/mitre/techniques/T1564-003.md): restores. Adversaries may use hidden windows to conceal malicious activity from the plain sight of users.
- [T1564.005: Hidden File System](/mitre/techniques/T1564-005.md): restores. Adversaries may use a hidden file system to conceal malicious activity from users and security tools.
- [T1614.001: System Language Discovery](/mitre/techniques/T1614-001.md): restores. Adversaries may attempt to gather information about the system language of a victim in order to infer the geographical location of that host.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
