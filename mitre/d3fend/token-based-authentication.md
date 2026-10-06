# D3FEND: Token-based Authentication

<a id="token-based-authentication"></a>

D3FEND tactic: Harden  
Digital artifacts: Access Token  

Token-based authentication is an authentication protocol where users verify their identity in exchange for a unique access token. Users can then access the website, application, or resource for the life of the token without having to re-enter their credentials.

## ATT&CK techniques countered (7)

- [T1134.001: Token Impersonation/Theft](/mitre/techniques/T1134-001.md): uses. Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls.
- [T1134.002: Create Process with Token](/mitre/techniques/T1134-002.md): uses. Adversaries may create a new process with an existing token to escalate privileges and bypass access controls.
- [T1134.003: Make and Impersonate Token](/mitre/techniques/T1134-003.md): uses. Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls.
- [T1528: Steal Application Access Token](/mitre/techniques/T1528.md): uses. Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.
- [T1550.001: Application Access Token](/mitre/techniques/T1550-001.md): uses. Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems.
- [T1558: Steal or Forge Kerberos Tickets](/mitre/techniques/T1558.md): uses. Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003).
- [T1558.001: Golden Ticket](/mitre/techniques/T1558-001.md): uses. Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
