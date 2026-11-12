# D3FEND: Multi-factor Authentication

<a id="multi-factor-authentication"></a>

D3FEND tactic: Harden  
Digital artifacts: Credential  

Requiring proof of two or more pieces of evidence in order to authenticate a user.

## ATT&CK techniques countered (23)

- [T0892: Change Credential](https://attack.mitre.org/techniques/T0892): uses
- [T1003.003: NTDS](/mitre/techniques/T1003-003.md): uses. Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights.
- [T1003.005: Cached Domain Credentials](/mitre/techniques/T1003-005.md): uses. Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable.
- [T1003.008: /etc/passwd and /etc/shadow](/mitre/techniques/T1003-008.md): uses. Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking.
- [T1098.001: Additional Cloud Credentials](/mitre/techniques/T1098-001.md): uses. Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.
- [T1110.001: Password Guessing](/mitre/techniques/T1110-001.md): uses. Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.
- [T1110.002: Password Cracking](/mitre/techniques/T1110-002.md): uses. Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained.
- [T1110.003: Password Spraying](/mitre/techniques/T1110-003.md): uses. Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.
- [T1134.001: Token Impersonation/Theft](/mitre/techniques/T1134-001.md): uses. Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls.
- [T1134.002: Create Process with Token](/mitre/techniques/T1134-002.md): uses. Adversaries may create a new process with an existing token to escalate privileges and bypass access controls.
- [T1134.003: Make and Impersonate Token](/mitre/techniques/T1134-003.md): uses. Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls.
- [T1528: Steal Application Access Token](/mitre/techniques/T1528.md): uses. Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.
- [T1539: Steal Web Session Cookie](/mitre/techniques/T1539.md): uses. An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials.
- [T1550.001: Application Access Token](/mitre/techniques/T1550-001.md): uses. Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems.
- [T1550.004: Web Session Cookie](/mitre/techniques/T1550-004.md): uses. Adversaries can use stolen session cookies to authenticate to web applications and services.
- [T1552: Unsecured Credentials](/mitre/techniques/T1552.md): uses. Adversaries may search compromised systems to find and obtain insecurely stored credentials.
- [T1555.001: Keychain](/mitre/techniques/T1555-001.md): uses (D3FEND maps the revoked predecessor T1142). Adversaries may acquire credentials from Keychain.
- [T1558: Steal or Forge Kerberos Tickets](/mitre/techniques/T1558.md): uses. Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003).
- [T1558.001: Golden Ticket](/mitre/techniques/T1558-001.md): uses. Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.
- [T1606: Forge Web Credentials](/mitre/techniques/T1606.md): uses. Adversaries may forge credential materials that can be used to gain access to web applications or Internet services.
- [T1606.001: Web Cookies](/mitre/techniques/T1606-001.md): uses. Adversaries may forge web cookies that can be used to gain access to web applications or Internet services.
- [T1694.001: Default Credentials](https://attack.mitre.org/techniques/T1694/001): uses (D3FEND maps the revoked predecessor T0812)
- [T1694.002: Hardcoded Credentials](https://attack.mitre.org/techniques/T1694/002): uses (D3FEND maps the revoked predecessor T0891)

## Related pages

- [Authentication Cache Invalidation](/mitre/d3fend/authentication-cache-invalidation.md), which also counters 23 of these techniques
- [Credential Compromise Scope Analysis](/mitre/d3fend/credential-compromise-scope-analysis.md), which also counters 23 of these techniques
- [Credential Hardening](/mitre/d3fend/credential-hardening.md), which also counters 23 of these techniques
- [Credential Revocation](/mitre/d3fend/credential-revocation.md), which also counters 23 of these techniques
- [Credential Rotation](/mitre/d3fend/credential-rotation.md), which also counters 23 of these techniques
- [Credential Transmission Scoping](/mitre/d3fend/credential-transmission-scoping.md), which also counters 23 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md)
- [Cybercrime and Hacktivism in Four Books: Kingpin, Fatal System Error, We Are Anonymous, The Hacker Crackdown](/case-studies/CYBERCRIME_FOUR_BOOKS.md)
- [Five Hacks and Why They Worked: The Cases in Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md)
- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md)
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)
- [npm Supply-Chain Attacks, 2018 to 2026: The Record and the Defenses](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md)
- [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md)
- [The Change Healthcare Attack of 2024: The Largest Healthcare Breach on Record](/case-studies/CHANGE_HEALTHCARE_2024.md)
- [The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986](/case-studies/CUCKOOS_EGG_1986.md)
- [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md)
- [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
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

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
