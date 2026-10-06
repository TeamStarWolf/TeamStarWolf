# D3FEND: Credential Transmission Scoping

<a id="credential-transmission-scoping"></a>

D3FEND tactic: Isolate  
Digital artifacts: Credential  

Limiting the transmission of a credential to a scoped set of relying parties.

## ATT&CK techniques countered (23)

- [T0812](https://attack.mitre.org/techniques/T0812): isolates
- [T0891](https://attack.mitre.org/techniques/T0891): isolates
- [T0892](https://attack.mitre.org/techniques/T0892): isolates
- [T1003.003: NTDS](/mitre/techniques/T1003-003.md): isolates. Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights.
- [T1003.005: Cached Domain Credentials](/mitre/techniques/T1003-005.md): isolates. Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable.
- [T1003.008: /etc/passwd and /etc/shadow](/mitre/techniques/T1003-008.md): isolates. Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking.
- [T1098.001: Additional Cloud Credentials](/mitre/techniques/T1098-001.md): isolates. Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.
- [T1110.001: Password Guessing](/mitre/techniques/T1110-001.md): isolates. Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.
- [T1110.002: Password Cracking](/mitre/techniques/T1110-002.md): isolates. Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained.
- [T1110.003: Password Spraying](/mitre/techniques/T1110-003.md): isolates. Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.
- [T1134.001: Token Impersonation/Theft](/mitre/techniques/T1134-001.md): isolates. Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls.
- [T1134.002: Create Process with Token](/mitre/techniques/T1134-002.md): isolates. Adversaries may create a new process with an existing token to escalate privileges and bypass access controls.
- [T1134.003: Make and Impersonate Token](/mitre/techniques/T1134-003.md): isolates. Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls.
- `T1142`: isolates
- [T1528: Steal Application Access Token](/mitre/techniques/T1528.md): isolates. Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.
- [T1539: Steal Web Session Cookie](/mitre/techniques/T1539.md): isolates. An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials.
- [T1550.001: Application Access Token](/mitre/techniques/T1550-001.md): isolates. Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems.
- [T1550.004: Web Session Cookie](/mitre/techniques/T1550-004.md): isolates. Adversaries can use stolen session cookies to authenticate to web applications and services.
- [T1552: Unsecured Credentials](/mitre/techniques/T1552.md): isolates. Adversaries may search compromised systems to find and obtain insecurely stored credentials.
- [T1558: Steal or Forge Kerberos Tickets](/mitre/techniques/T1558.md): isolates. Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003).
- [T1558.001: Golden Ticket](/mitre/techniques/T1558-001.md): isolates. Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.
- [T1606: Forge Web Credentials](/mitre/techniques/T1606.md): isolates. Adversaries may forge credential materials that can be used to gain access to web applications or Internet services.
- [T1606.001: Web Cookies](/mitre/techniques/T1606-001.md): isolates. Adversaries may forge web cookies that can be used to gain access to web applications or Internet services.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
