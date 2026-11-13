# D3FEND: Credential Rotation

<a id="credential-rotation"></a>

D3FEND tactic: Harden  
Digital artifacts: Credential  

Credential rotation is a security procedure in which authentication credentials, such as passwords, API keys, or certificates, are regularly changed or replaced to minimize the risk of unauthorized access.

## ATT&CK techniques countered (23)

- [T0892: Change Credential](https://attack.mitre.org/techniques/T0892): regenerates
- [T1003.003: NTDS](/mitre/techniques/T1003-003.md): regenerates. Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights.
- [T1003.005: Cached Domain Credentials](/mitre/techniques/T1003-005.md): regenerates. Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable.
- [T1003.008: /etc/passwd and /etc/shadow](/mitre/techniques/T1003-008.md): regenerates. Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking.
- [T1098.001: Additional Cloud Credentials](/mitre/techniques/T1098-001.md): regenerates. Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.
- [T1110.001: Password Guessing](/mitre/techniques/T1110-001.md): regenerates. Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.
- [T1110.002: Password Cracking](/mitre/techniques/T1110-002.md): regenerates. Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained.
- [T1110.003: Password Spraying](/mitre/techniques/T1110-003.md): regenerates. Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.
- [T1134.001: Token Impersonation/Theft](/mitre/techniques/T1134-001.md): regenerates. Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls.
- [T1134.002: Create Process with Token](/mitre/techniques/T1134-002.md): regenerates. Adversaries may create a new process with an existing token to escalate privileges and bypass access controls.
- [T1134.003: Make and Impersonate Token](/mitre/techniques/T1134-003.md): regenerates. Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls.
- [T1528: Steal Application Access Token](/mitre/techniques/T1528.md): regenerates. Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.
- [T1539: Steal Web Session Cookie](/mitre/techniques/T1539.md): regenerates. An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials.
- [T1550.001: Application Access Token](/mitre/techniques/T1550-001.md): regenerates. Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems.
- [T1550.004: Web Session Cookie](/mitre/techniques/T1550-004.md): regenerates. Adversaries can use stolen session cookies to authenticate to web applications and services.
- [T1552: Unsecured Credentials](/mitre/techniques/T1552.md): regenerates. Adversaries may search compromised systems to find and obtain insecurely stored credentials.
- [T1555.001: Keychain](/mitre/techniques/T1555-001.md): regenerates (D3FEND maps the revoked predecessor T1142). Adversaries may acquire credentials from Keychain.
- [T1558: Steal or Forge Kerberos Tickets](/mitre/techniques/T1558.md): regenerates. Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003).
- [T1558.001: Golden Ticket](/mitre/techniques/T1558-001.md): regenerates. Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.
- [T1606: Forge Web Credentials](/mitre/techniques/T1606.md): regenerates. Adversaries may forge credential materials that can be used to gain access to web applications or Internet services.
- [T1606.001: Web Cookies](/mitre/techniques/T1606-001.md): regenerates. Adversaries may forge web cookies that can be used to gain access to web applications or Internet services.
- [T1694.001: Default Credentials](https://attack.mitre.org/techniques/T1694/001): regenerates (D3FEND maps the revoked predecessor T0812)
- [T1694.002: Hardcoded Credentials](https://attack.mitre.org/techniques/T1694/002): regenerates (D3FEND maps the revoked predecessor T0891)

## Related pages

- [Authentication Cache Invalidation](/mitre/d3fend/authentication-cache-invalidation.md), which also counters 23 of these techniques
- [Credential Compromise Scope Analysis](/mitre/d3fend/credential-compromise-scope-analysis.md), which also counters 23 of these techniques
- [Credential Hardening](/mitre/d3fend/credential-hardening.md), which also counters 23 of these techniques
- [Credential Revocation](/mitre/d3fend/credential-revocation.md), which also counters 23 of these techniques
- [Credential Transmission Scoping](/mitre/d3fend/credential-transmission-scoping.md), which also counters 23 of these techniques
- [Decoy User Credential](/mitre/d3fend/decoy-user-credential.md), which also counters 23 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md)
- [Collabora Built-in CODE Server (richdocumentscode), CVE-2026-110447: Lab-Verified Exposure and Fix](/case-studies/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md)
- [Magento and Adobe Commerce, CVE-2026-48356: Lab-Verified Exposure and Fix](/case-studies/MAGENTO_CVE_2026_48356.md)
- [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md)
- [npm Supply-Chain Attacks, 2018 to 2026: The Record and the Defenses](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md)
- [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md)
- [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md)
- [SSHole: The OpenSSH Authentication Bypass of November 2026 (CVE-2026-123158)](/case-studies/SSHOLE_CVE_2026_123158.md)
- [The Binance Hot-Wallet Theft of October 2026: A Case Study](/case-studies/BINANCE_HEIST_2026.md)
- [The Boston Scientific Network Outage of August 2026: A Case Study](/case-studies/BOSTON_SCIENTIFIC_ATTACK_2026.md)
- [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md)
- [The ConnectWise Cloud Backup Compromise of October 2026: A Case Study](/case-studies/CONNECTWISE_STORM_0940_2026.md)
- [The cPanel and WHM Authentication Bypass of 2026 (CVE-2026-41940): A Case Study](/case-studies/CPANEL_WHM_CVE_2026_41940.md)
- [The European Commission Cloud Breach of 2026: AWS Data Theft Through the Poisoned Trivy Scanner](/case-studies/EUROPEAN_COMMISSION_CLOUD_BREACH_2026.md)
- [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md)
- [The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md)
- [The Instructure Canvas Breach and ShinyHunters Extortion of 2026: A Case Study](/case-studies/INSTRUCTURE_CANVAS_BREACH_2026.md)
- [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md)
- [The PAN-OS GlobalProtect Authentication Bypass of 2026 (CVE-2026-0257), Qilin and INC Ransomware: A Case Study](/case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md)
- [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md)
- [The TeamPCP Supply-Chain Campaign of 2026: Trivy, Checkmarx and the Bitwarden CLI (CVE-2026-33634)](/case-studies/TEAMPCP_TRIVY_SUPPLY_CHAIN_2026.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md)
- [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)
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
